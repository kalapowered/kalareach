//! The device scripts start KalaReach's own Android virtual device and no other.
//!
//! Every other virtual device on a machine belongs to other work, so a script that takes the first
//! one listed, or defaults to a name that is someone else's, starts, fills and wipes what is not
//! KalaReach's. Each case runs a script as it is committed, from a copy of the tree, with the
//! Android tools replaced by programs that record their arguments and start nothing: the SDK's
//! `adb` and `emulator`, and the build tools, Gradle wrapper, browser and image reader a script
//! calls before it reaches the device. Every script is run to the point where it starts the
//! emulator, so the arguments the emulator was given are what the cases read.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use tempfile::TempDir;

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

const KALAREACH: &str = "KalaReach_API_36_Play";
const OTHERS: [&str; 3] = ["Nines_API_36_Play", "Emberdeck_API_37", "Nines20_Tablet"];

/// A script that starts an emulator, and what it takes to get that far.
struct Script {
    path: &'static str,
    args: &'static [&'static str],
    /// Whether the script waits for the device to report that it has booted.
    waits_for_boot: bool,
    /// What the script is told in its environment to get as far as the device.
    env: &'static [(&'static str, &'static str)],
}

const SCRIPTS: [Script; 12] = [
    Script {
        path: "scripts/e2e-mobile.sh",
        args: &["android"],
        waits_for_boot: true,
        env: &[],
    },
    Script {
        path: "scripts/e2e-voice-device.sh",
        args: &["android"],
        waits_for_boot: false,
        env: &[],
    },
    Script {
        path: "scripts/e2e-voice-call-bridge.sh",
        args: &["android"],
        waits_for_boot: false,
        env: &[],
    },
    Script {
        path: "scripts/e2e-voice-call-device.sh",
        args: &["android"],
        waits_for_boot: false,
        env: &[],
    },
    Script {
        path: "apps/companion/e2e/android-stores.sh",
        args: &["application.apk"],
        waits_for_boot: false,
        env: &[],
    },
    Script {
        path: "apps/companion/e2e/standing-emulator.sh",
        args: &[],
        waits_for_boot: false,
        env: &[],
    },
    Script {
        path: "apps/companion/e2e/system-text-size-android.sh",
        args: &["application.apk"],
        waits_for_boot: false,
        env: &[],
    },
    Script {
        path: "scripts/e2e-pairing-device.sh",
        args: &["android"],
        waits_for_boot: false,
        env: &[],
    },
    Script {
        // The package it installs is named, so the script goes no further than the device for it.
        path: "scripts/e2e-android-release.sh",
        args: &[],
        waits_for_boot: false,
        env: &[("KR_RELEASE_APK", "application.apk")],
    },
    Script {
        // The web checkout the gateway runs from and the package to install are named, so the
        // script goes no further than the device for them.
        path: "scripts/e2e-push-device.sh",
        args: &["android"],
        waits_for_boot: false,
        env: &[
            ("KR_WEB_TREE", "web"),
            ("KR_PUSH_ANDROID_APK", "application.apk"),
        ],
    },
    Script {
        path: "scripts/e2e-push-android-receiver.sh",
        args: &[],
        waits_for_boot: false,
        env: &[],
    },
    Script {
        // The bundle and its record are named, so the script goes no further than the device for
        // them: it makes the package the device installs, and starts the emulator.
        path: "scripts/store-android.sh",
        args: &["--device", "store-output"],
        waits_for_boot: false,
        env: &[],
    },
];

/// What a run of a script said and asked of the tools.
struct Run {
    output: String,
    status: Option<i32>,
    /// Every call to a stand-in, in order, one line each: the program, then its arguments.
    calls: Vec<String>,
    /// The case's directory, which a case reads for what the script left in it.
    directory: TempDir,
}

/// What a machine has beyond the virtual devices its emulator lists and the one that is running.
#[derive(Default)]
struct Setup<'a> {
    /// The virtual device that answers on whatever serial the script gives its emulator once that
    /// emulator, which stays up until the script that started it has gone or has asked it to stop,
    /// has booted. The device is not listed before the script starts its own.
    boots_as: Option<&'a str>,
    /// Output folders of an earlier run that anyone could read, holding a file anyone could read.
    readable_outputs: bool,
    /// The device refuses every installation, so that a script that goes on to install ends there.
    installs_fail: bool,
}

impl Run {
    /// The virtual devices the emulator was asked to start.
    fn started(&self) -> Vec<String> {
        self.calls
            .iter()
            .filter_map(|call| {
                let words: Vec<&str> = call.split_whitespace().collect();
                if words.first() != Some(&"emulator") {
                    return None;
                }
                // The emulator takes a device as `-avd <name>` or as `@<name>`.
                if let Some(at) = words.iter().position(|word| *word == "-avd") {
                    return words.get(at + 1).map(|name| (*name).to_string());
                }
                words
                    .iter()
                    .find_map(|word| word.strip_prefix('@'))
                    .map(str::to_string)
            })
            .collect()
    }

    fn called(&self, program_and_start_of_arguments: &str) -> bool {
        self.calls
            .iter()
            .any(|call| call.starts_with(program_and_start_of_arguments))
    }

    fn calling_contains(&self, program: &str, word: &str) -> bool {
        self.calls.iter().any(|call| {
            let mut words = call.split_whitespace();
            words.next() == Some(program) && words.any(|found| found == word)
        })
    }
}

/// A program that appends its own name and arguments to the record, then runs `body`.
///
/// It is placed by a process that starts nothing else, so that no thread of this test binary
/// holds it open for writing when another starts it.
fn stand_in(directory: &Path, name: &str, record: &Path, body: &str) {
    let path = directory.join(name);
    fs::create_dir_all(directory).expect("a directory");
    let text = directory.join(format!("{name}.text"));
    fs::write(
        &text,
        format!(
            "#!/bin/sh\necho \"{name} $*\" >>\"{}\"\n{body}\n",
            record.display()
        ),
    )
    .expect("a stand-in");
    kr_ipc::testing::place_program(&text, &path);
}

fn copy_into(root: &Path, relative: &str) {
    let target = root.join(relative);
    fs::create_dir_all(target.parent().expect("a parent")).expect("a directory");
    fs::copy(repository().join(relative), target).expect("the script copies");
}

/// Copies every file directly under `relative`, the libraries the scripts source.
fn copy_directory_into(root: &Path, relative: &str) {
    for entry in fs::read_dir(repository().join(relative)).expect("the libraries") {
        let entry = entry.expect("an entry");
        if entry.path().is_file() {
            copy_into(
                root,
                &format!("{relative}/{}", entry.file_name().to_string_lossy()),
            );
        }
    }
}

/// How long a script's background jobs are given to end once the script has: the emulator's
/// stand-in records its call and ends, and the page server's stand-in ends with the script, so
/// this is only what a loaded machine adds to the moments they need.
const JOBS_END_WITHIN: Duration = Duration::from_secs(60);

/// How long a script is given to end. A script runs to the point where it starts the emulator, and
/// the longest takes seconds; one that waits for a device that is not there waits for good.
const SCRIPT_ENDS_WITHIN: Duration = Duration::from_secs(300);

/// Whether `child`, which has been told to end, is collected within `within`. A child that does not
/// go in that time (one stuck in the kernel) is reported and not waited for.
fn collected_within(child: &mut std::process::Child, within: Duration) -> bool {
    let gone = Instant::now() + within;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return true,
            Ok(None) if Instant::now() < gone => std::thread::sleep(Duration::from_millis(5)),
            Ok(None) | Err(_) => return false,
        }
    }
}

/// Runs `command` to its end within `bound`, ending it when it has not ended, and gives what it
/// printed. A command that outlasts the bound, or that leaves something running which holds its
/// output, fails the case with the command named, where a wait for it would hold the suite.
fn to_its_end(command: Command, bound: Duration) -> std::process::Output {
    to_its_end_with_streams(command, bound, None)
}

/// [`to_its_end`], giving what the command printed `streams_within` to reach its end where it
/// ended, where it is otherwise given what is left of `bound` and at least a second.
fn to_its_end_with_streams(
    mut command: Command,
    bound: Duration,
    streams_within: Option<Duration>,
) -> std::process::Output {
    use std::process::Stdio;

    fn read_aside(
        mut stream: impl std::io::Read + Send + 'static,
    ) -> std::sync::mpsc::Receiver<Vec<u8>> {
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = stream.read_to_end(&mut bytes);
            let _ = sender.send(bytes);
        });
        receiver
    }

    let what = format!("{command:?}");
    let begun = Instant::now();
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("{what} could not be started: {error}"));
    let stdout = read_aside(child.stdout.take().expect("its standard output"));
    let stderr = read_aside(child.stderr.take().expect("its standard error"));
    let status = loop {
        match child.try_wait().expect("its state") {
            Some(status) => break status,
            None if begun.elapsed() < bound => std::thread::sleep(Duration::from_millis(5)),
            None => {
                let _ = child.kill();
                // A killed process is collected within a time of its own, and a process that does
                // not go (one stuck in the kernel) is said to still be there.
                let ended = collected_within(&mut child, Duration::from_secs(10));
                panic!(
                    "{what} did not end within {bound:?}{}",
                    if ended {
                        ""
                    } else {
                        ", and was still there 10 s after it was killed"
                    }
                );
            }
        }
    };
    let rest = streams_within.unwrap_or_else(|| {
        bound
            .saturating_sub(begun.elapsed())
            .max(Duration::from_secs(1))
    });
    let collect = |stream: &std::sync::mpsc::Receiver<Vec<u8>>| {
        stream.recv_timeout(rest).unwrap_or_else(|_| {
            panic!("{what} ended and something it started still holds its output after {rest:?}")
        })
    };
    let out = collect(&stdout);
    let err = collect(&stderr);
    std::process::Output {
        status,
        stdout: out,
        stderr: err,
    }
}

/// `path` as an extended regular expression that matches it as it is written and ends at the end
/// of a name: the next character is not one a name is made of, or the line ends.
fn as_a_directory_pattern(path: &Path) -> String {
    let mut pattern = String::new();
    for character in path.to_string_lossy().chars() {
        if r"\.[]{}()*+?|^$".contains(character) {
            pattern.push('\\');
        }
        pattern.push(character);
    }
    pattern.push_str("([^A-Za-z0-9._-]|$)");
    pattern
}

/// Returns once no process has `root`, the directory the case made, in its command line: the script
/// and every job it started from there (each runs a program of the case's own) are over, and the
/// record holds every call they made.
///
/// A job the script put in the background is not waited for by the script or by the case's read of
/// its output, and a script that fails soon after starting the emulator can end first. A process
/// that is being replaced by another program can show no command line for a moment, so the
/// directory has to be found by no look twice, a moment apart, before the jobs count as over.
fn until_nothing_of_the_case_runs(root: &Path) {
    until_nothing_runs_in(Path::new("pgrep"), root, JOBS_END_WITHIN);
}

/// [`until_nothing_of_the_case_runs`], asking the processes' command lines of `pgrep`, a program
/// that is given `ends_within` for the whole wait and for each look.
fn until_nothing_runs_in(pgrep: &Path, root: &Path, ends_within: Duration) {
    let pattern = as_a_directory_pattern(root);
    let begun = Instant::now();
    let mut unseen = 0;
    while unseen < 2 {
        let mut look = Command::new(pgrep);
        look.arg("-f").arg("--").arg(&pattern);
        let left = ends_within.saturating_sub(begun.elapsed());
        // A look that blocks, on a process whose command line cannot be read, is bounded by what
        // is left of the wait.
        let found = to_its_end(look, left.max(Duration::from_secs(1))).status;
        // 0 when some process matches, 1 when none does; anything else is pgrep's own failure.
        match found.code() {
            Some(1) => unseen += 1,
            Some(0) => {
                unseen = 0;
                assert!(
                    begun.elapsed() < ends_within,
                    "something the script started in {} was still running {ends_within:?} after \
                     it ended",
                    root.display()
                );
            }
            other => panic!("pgrep ended with {other:?} for {pattern}"),
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Runs `script` from a copy of the tree on a machine whose emulator lists `listed`, with the
/// virtual device `running` (an emulator serial and the name of its device) already up, if any.
fn run(
    script: &Script,
    listed: &[&str],
    running: Option<(&str, &str)>,
    extra: &[(&str, &str)],
) -> Run {
    run_with(script, listed, running, extra, &Setup::default())
}

/// [`run`] on a machine that is also as `setup` says.
fn run_with(
    script: &Script,
    listed: &[&str],
    running: Option<(&str, &str)>,
    extra: &[(&str, &str)],
    setup: &Setup,
) -> Run {
    let directory = TempDir::new().expect("a directory");
    let root = directory.path();
    let tree = root.join("tree");
    let tools = root.join("tools");
    let sdk = root.join("sdk");
    let record = root.join("calls.log");
    fs::write(&record, "").expect("a record");

    copy_into(&tree, script.path);
    copy_directory_into(&tree, "scripts/lib");
    // What the scripts that serve or open the harness, and the one that installs an application,
    // look for in the tree before they reach the device.
    let companion = tree.join("apps/companion");
    fs::create_dir_all(companion.join("dist-harness")).expect("a directory");
    fs::write(companion.join("dist-harness/harness.html"), "").expect("a page");
    let package = companion.join(
        "src-tauri/gen/android/app/build/outputs/apk/universal/debug/app-universal-debug.apk",
    );
    fs::create_dir_all(package.parent().expect("a parent")).expect("a directory");
    fs::write(package, "").expect("a package");
    fs::write(tree.join("application.apk"), "").expect("a package");
    // What the receiver's script builds with and installs from, and the built web checkout the push
    // script starts its gateway from (it refuses a tree that lacks the driver or the built site
    // before it starts anything or builds, which is why the stand-in has both).
    let android = companion.join("src-tauri/gen/android");
    let outputs = android.join("app/build/outputs/apk");
    for package in [
        "arm64/debug/app-arm64-debug.apk",
        "androidTest/arm64/debug/app-arm64-debug-androidTest.apk",
    ] {
        let package = outputs.join(package);
        fs::create_dir_all(package.parent().expect("a parent")).expect("a directory");
        fs::write(package, "").expect("a package");
    }
    let driver = tree.join("web/infra/scripts/testing/local-restore.mjs");
    fs::create_dir_all(driver.parent().expect("a parent")).expect("a directory");
    fs::write(driver, "").expect("a driver");
    fs::create_dir_all(tree.join("web/apps/site/dist")).expect("a built site");

    // What the store script's device run reads before it reaches the device: the record of a bundle
    // that holds and the bundle, the upload key's files with the access they are kept with, and the
    // Java tools and the bundle tool it looks for.
    let output = tree.join("store-output");
    fs::create_dir_all(&output).expect("a directory");
    fs::write(
        output.join("store-build.json"),
        "{\"holds\": true, \"versionCode\": 39850, \"file\": \"KalaReach.aab\"}",
    )
    .expect("a record");
    fs::write(output.join("KalaReach.aab"), "").expect("a bundle");
    let upload = root.join("secrets/android-upload");
    fs::create_dir_all(&upload).expect("a directory");
    for name in ["kalareach-upload.p12", "keystore-password"] {
        fs::write(upload.join(name), "made for the case\n").expect("a key file");
        fs::set_permissions(upload.join(name), fs::Permissions::from_mode(0o600))
            .expect("kept private");
    }
    fs::write(upload.join("upload-certificate.pem"), "").expect("a certificate");
    for tool in ["jarsigner", "keytool"] {
        stand_in(&root.join("java/bin"), tool, &record, "exit 0");
    }

    fs::write(root.join("avds.txt"), format!("{}\n", listed.join("\n"))).expect("a list");
    if let Some((serial, name)) = running {
        fs::write(root.join("running.txt"), format!("{serial}\tdevice\n")).expect("a device");
        fs::write(root.join("running-avd.txt"), format!("{name}\n")).expect("a name");
    }
    if script.waits_for_boot || setup.boots_as.is_some() {
        fs::write(root.join("booted"), "").expect("a flag");
    }
    if let Some(name) = setup.boots_as {
        fs::write(root.join("running-avd.txt"), format!("{name}\n")).expect("a name");
    }
    if setup.installs_fail {
        fs::write(root.join("installs-fail"), "").expect("a flag");
    }
    if setup.readable_outputs {
        let folder = root.join("artefacts/pairing-device-android");
        fs::create_dir_all(&folder).expect("a directory");
        fs::write(folder.join("earlier.log"), "an earlier run\n").expect("a log");
        fs::set_permissions(&folder, fs::Permissions::from_mode(0o755)).expect("readable");
        fs::set_permissions(
            folder.join("earlier.log"),
            fs::Permissions::from_mode(0o644),
        )
        .expect("readable");
        let shots = root.join("shots");
        fs::create_dir_all(&shots).expect("a directory");
        fs::write(shots.join("earlier.png"), "a picture\n").expect("a picture");
        fs::set_permissions(&shots, fs::Permissions::from_mode(0o755)).expect("readable");
        fs::set_permissions(shots.join("earlier.png"), fs::Permissions::from_mode(0o644))
            .expect("readable");
    }

    // The SDK's two programs. The emulator lists what the machine has and, asked to start a
    // device, only records it. The debug bridge reports the running emulator and its device, and
    // says the boot is complete only where a script waits for that.
    let stopped = root.join("emulator-stopped");
    stand_in(
        &sdk.join("emulator"),
        "emulator",
        &record,
        &format!(
            "[ \"$1\" = -list-avds ] && cat \"{}\"\n{}exit 0",
            root.join("avds.txt").display(),
            // A device that boots stays up until the script that started it has gone or has asked
            // it to stop, as the real one does.
            if setup.boots_as.is_some() {
                // It is listed by `adb devices` from the moment it is started, on the console port it
                // was given.
                format!(
                    "[ \"$1\" = -list-avds ] || {{ previous=; for each in \"$@\"; do [ \"$previous\" = -port ] && printf 'emulator-%s\\tdevice\\n' \"$each\" >\"{}\"; previous=$each; done; while [ ! -e \"{}\" ] && kill -0 \"$PPID\" 2>/dev/null; do sleep 0.2; done; }}\n",
                    root.join("started.txt").display(),
                    stopped.display()
                )
            } else {
                String::new()
            }
        ),
    );
    stand_in(
        &sdk.join("platform-tools"),
        "adb",
        &record,
        &format!(
            "case \"$*\" in\n\
             *'emu kill'*) : >\"{stopped}\" ;;\n\
             *install*) [ -f \"{installs_fail}\" ] && exit 1 ;;\n\
             *'emu avd name'*) [ -f \"{running_avd}\" ] && {{ cat \"{running_avd}\"; echo OK; }} ;;\n\
             *getprop*sys.boot_completed*) [ -f \"{booted}\" ] && echo 1 ;;\n\
             *getprop*) echo stand-in ;;\n\
             devices*) echo 'List of devices attached'; [ -f \"{running}\" ] && cat \"{running}\"; [ -f \"{started}\" ] && cat \"{started}\" ;;\n\
             esac\nexit 0",
            running_avd = root.join("running-avd.txt").display(),
            booted = root.join("booted").display(),
            running = root.join("running.txt").display(),
            started = root.join("started.txt").display(),
            installs_fail = root.join("installs-fail").display(),
            stopped = stopped.display(),
        ),
    );

    // The Gradle wrapper builds nothing and says so in the record.
    stand_in(&android, "gradlew", &record, "exit 0");

    // The signer and the aligner a release run looks for before it builds anything.
    for tool in ["apksigner", "zipalign"] {
        stand_in(&sdk.join("build-tools/36.0.0"), tool, &record, "exit 0");
    }

    // What a script calls on the way to the device. A build succeeds without building, and the
    // host build names an executable as cargo does; the page server stays up until the script that
    // started it has gone, as the real one does; nothing is already serving; the image reader does
    // not compile, so no check of a picture can pass.
    stand_in(&tools, "pnpm", &record, "exit 0");
    stand_in(&tools, "voice_device", &record, "exit 0");
    stand_in(
        &tools,
        "cargo",
        &record,
        &format!(
            "case \"$*\" in\n\
             *--message-format=json*) for host in voice_device pairing_device release_tls_device push_device; do echo '{{\"reason\":\"compiler-artifact\",\"executable\":\"{path}\",\"target\":{{\"name\":\"'$host'\"}}}}'; done ;;\n\
             *) exit 1 ;;\n\
             esac",
            path = tools.join("voice_device").display()
        ),
    );
    // Python reads what the build said, and the checks of a package and the driver of the emulator
    // run on a device that is not there: they say nothing and succeed.
    stand_in(
        &tools,
        "python3",
        &record,
        "case \"$1\" in\n\
         */android-network-config.py | */pairing-android.py) exit 0 ;;\n\
         esac\n\
         exec /usr/bin/python3 \"$@\"",
    );
    // The store script's checker only filters the text it is given, and its device run reads three
    // fields of the record of a bundle that holds.
    stand_in(
        &tools,
        "node",
        &record,
        "case \"$1\" in\n\
         -e) case \"$2\" in\n\
         *.holds*) printf true; exit 0 ;;\n\
         *.versionCode*) printf 39850; exit 0 ;;\n\
         *.file*) printf KalaReach.aab; exit 0 ;;\n\
         esac ;;\n\
         esac\n\
         case \"$*\" in *--redact*) cat; exit 0 ;; esac\n\
         if [ \"$1\" = scripts/preview-harness.mjs ]; then\n\
         while kill -0 \"$3\" 2>/dev/null; do sleep 0.2; done\nexit 0\nfi\nexit 1",
    );
    // The bundle tool makes the set of packages that holds the universal one; the access a file is
    // kept with is read the way macOS reads it.
    stand_in(
        &tools,
        "bundletool",
        &record,
        "for argument in \"$@\"; do case \"$argument\" in --output=*) out=\"${argument#--output=}\" ;; esac; done\n\
         [ -z \"${out:-}\" ] || exec /usr/bin/python3 -c 'import sys, zipfile; zipfile.ZipFile(sys.argv[1], \"w\").writestr(\"universal.apk\", \"\")' \"$out\"\n\
         exit 0",
    );
    stand_in(
        &tools,
        "stat",
        &record,
        "case \"$*\" in\n\
         *%Lp*) echo 600 ;;\n\
         *) exec /usr/bin/stat \"$@\" ;;\n\
         esac",
    );
    stand_in(
        &tools,
        "curl",
        &record,
        "case \"$*\" in *-fsS*) exit 0 ;; esac\nexit 1",
    );
    stand_in(&tools, "swiftc", &record, "exit 1");
    stand_in(&tools, "nc", &record, "exit 1");
    stand_in(
        &tools,
        "uuidgen",
        &record,
        "echo 6f0c2b1e-3a4d-4c5b-8e7f-0a1b2c3d4e5f",
    );
    stand_in(
        &tools,
        "timeout",
        &record,
        "while :; do case \"$1\" in --foreground) shift ;; -k) shift 2 ;; *) break ;; esac; done\n\
         shift\nexec \"$@\"",
    );

    fs::create_dir_all(root.join("home")).expect("a directory");
    fs::create_dir_all(root.join("scratch")).expect("a directory");
    let mut command = Command::new("/bin/bash");
    command
        .arg(tree.join(script.path))
        .args(script.args)
        .current_dir(&tree)
        .env_clear()
        .env("PATH", format!("{}:/usr/bin:/bin", tools.display()))
        .env("HOME", root.join("home"))
        .env("TMPDIR", root.join("scratch"))
        .env("ANDROID_HOME", &sdk)
        .env("KR_TEST_ARTIFACTS_DIR", root.join("artefacts"))
        .env("KR_MOBILE_SCREENSHOT_DIR", root.join("scratch"))
        .env("KR_PAIRING_SHOTS", root.join("shots"))
        // A port nothing answers on, so that a machine that has an emulator's controller up does not
        // refuse the pairing script's cases; the case that wants a taken port names one.
        .env("KR_PAIRING_GRPC_PORT", free_port().to_string())
        .env("KR_PUSH_SHOTS", root.join("scratch"))
        .env("KR_STANDING_SHOTS", root.join("scratch"))
        .env("KR_TEXT_SIZE_SHOTS", root.join("scratch"))
        .env("KR_MOBILE_SETTLE", "0")
        .env("KR_SECRETS_DIR", root.join("secrets"))
        .env("KR_STORE_ROOT", root.join("store"))
        .env("KR_JAVA_HOME", root.join("java"))
        .env("KR_BUNDLETOOL", tools.join("bundletool"));
    for (name, value) in script.env.iter().chain(extra.iter()) {
        command.env(name, value);
    }
    let output = to_its_end(command, SCRIPT_ENDS_WITHIN);
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    // A script starts its emulator as a background job and may end before that job has run its
    // first line, so what the record holds is read once nothing of the case is left running.
    until_nothing_of_the_case_runs(root);
    let calls = fs::read_to_string(&record)
        .expect("the record")
        .lines()
        .map(str::to_string)
        .collect();
    Run {
        output: text,
        status: output.status.code(),
        calls,
        directory,
    }
}

/// A port of the loopback interface that nothing answers on.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("a port")
        .local_addr()
        .expect("its address")
        .port()
}

#[test]
fn a_machine_that_lacks_kalareachs_virtual_device_is_told_so_and_no_other_is_started() {
    let mut problems = Vec::new();
    for script in &SCRIPTS {
        let run = run(script, &OTHERS, None, &[]);
        let mut wrong = Vec::new();
        if !run.output.contains(KALAREACH) {
            wrong.push(format!("it did not name {KALAREACH}"));
        }
        if run.status == Some(0) {
            wrong.push("it ran to its end".to_string());
        }
        if !run.started().is_empty() {
            wrong.push(format!("it started {:?}", run.started()));
        }
        // A refusal costs the scripts that build the application (and the ones that build the
        // host) no build.
        if run.called("pnpm android") || run.called("cargo") || run.called("gradlew") {
            wrong.push("it built before it refused".to_string());
        }
        if !wrong.is_empty() {
            problems.push(format!(
                "{}: {}\n{}",
                script.path,
                wrong.join(", "),
                run.output
            ));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

#[test]
fn kalareachs_virtual_device_is_the_one_started_whatever_else_is_listed() {
    let listed = [OTHERS[0], OTHERS[1], KALAREACH, OTHERS[2]];
    let mut problems = Vec::new();
    for script in &SCRIPTS {
        let run = run(script, &listed, None, &[]);
        if run.started() != [KALAREACH] {
            problems.push(format!(
                "{} started {:?}\n{}",
                script.path,
                run.started(),
                run.output
            ));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// KalaReach's own device is the only one a script starts: the environment may repeat its name, and
/// a name it gives that is another's, listed or not, is refused by every script before anything is
/// built or started.
#[test]
fn a_virtual_device_the_environment_names_is_started_only_when_it_is_kalareachs() {
    let listed = [OTHERS[0], OTHERS[1], KALAREACH, "KalaReach_API_36_Tablet"];
    let mut problems = Vec::new();
    for script in &SCRIPTS {
        for refused in [OTHERS[0], "KalaReach_API_36_Tablet"] {
            let run = run(script, &listed, None, &[("KR_ANDROID_AVD", refused)]);
            let mut wrong = Vec::new();
            if !run.output.contains(refused) {
                wrong.push(format!("it did not name {refused}"));
            }
            if run.status == Some(0) {
                wrong.push("it ran to its end".to_string());
            }
            if !run.started().is_empty() {
                wrong.push(format!("it started {:?}", run.started()));
            }
            if run.called("pnpm android") || run.called("cargo") || run.called("gradlew") {
                wrong.push("it built before it refused".to_string());
            }
            if !wrong.is_empty() {
                problems.push(format!(
                    "{} given {refused}: {}\n{}",
                    script.path,
                    wrong.join(", "),
                    run.output
                ));
            }
        }
        let own = run(script, &listed, None, &[("KR_ANDROID_AVD", KALAREACH)]);
        if own.started() != [KALAREACH] {
            problems.push(format!(
                "{} given {KALAREACH} started {:?}\n{}",
                script.path,
                own.started(),
                own.output
            ));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// A device that took the emulator's serial before the script's own emulator booted answers the boot
/// wait too. The pairing script asks the device on its serial for its name, and when that is not
/// KalaReach's it installs nothing into it, changes nothing in it and does not stop it.
#[test]
fn a_device_on_the_pairing_scripts_serial_that_is_not_kalareachs_is_left_alone() {
    let pairing = pairing_script();
    let other = run_with(
        pairing,
        &[OTHERS[0], KALAREACH],
        None,
        &[],
        &Setup {
            boots_as: Some(OTHERS[0]),
            ..Setup::default()
        },
    );
    assert_eq!(other.status, Some(3), "{}", other.output);
    assert!(other.output.contains(OTHERS[0]), "{}", other.output);
    assert_eq!(other.started(), [KALAREACH]);
    for word in [
        "install",
        "uninstall",
        "reverse",
        "kill",
        "locksettings",
        "pm",
        "log",
    ] {
        assert!(
            !other.calling_contains("adb", word),
            "the script went on with another project's device ({word}):\n{}",
            other.calls.join("\n")
        );
    }
    assert!(
        !other
            .calls
            .iter()
            .any(|call| call.starts_with("python3") && call.contains("pairing-android.py")),
        "the camera was moved:\n{}",
        other.calls.join("\n")
    );

    // The same machine with KalaReach's device on the serial goes on to install.
    let own = run_with(
        pairing,
        &[OTHERS[0], KALAREACH],
        None,
        &[],
        &Setup {
            boots_as: Some(KALAREACH),
            ..Setup::default()
        },
    );
    assert!(
        own.calling_contains("adb", "install"),
        "{}\n{}",
        own.output,
        own.calls.join("\n")
    );
    assert!(own.calling_contains("adb", "kill"), "{}", own.output);
}

/// The scripts that start an emulator on a serial of their own: every script here but the one that
/// uses whatever emulator is listed.
const OWN_SERIAL: [&str; 11] = [
    "scripts/e2e-pairing-device.sh",
    "scripts/e2e-android-release.sh",
    "scripts/e2e-push-device.sh",
    "scripts/e2e-push-android-receiver.sh",
    "scripts/store-android.sh",
    "scripts/e2e-voice-call-bridge.sh",
    "scripts/e2e-voice-call-device.sh",
    "scripts/e2e-voice-device.sh",
    "apps/companion/e2e/android-stores.sh",
    "apps/companion/e2e/standing-emulator.sh",
    "apps/companion/e2e/system-text-size-android.sh",
];
/// The ones among them that go on to install into the device, whose control run is ended by the
/// device refusing the installation.
const INSTALLS: [&str; 7] = [
    "scripts/e2e-pairing-device.sh",
    "scripts/e2e-android-release.sh",
    "scripts/e2e-push-device.sh",
    "scripts/e2e-push-android-receiver.sh",
    "scripts/store-android.sh",
    "scripts/e2e-voice-call-bridge.sh",
    "scripts/e2e-voice-call-device.sh",
];

/// Whether a call to the debug bridge only reads: lists the devices, reads a property, asks a device
/// its name.
fn only_reads(call: &str) -> bool {
    let mut words = call.split_whitespace().skip(1).peekable();
    if words.peek() == Some(&"-s") {
        words.nth(1);
    }
    matches!(
        (words.next(), words.next(), words.next()),
        (Some("devices"), _, _)
            | (Some("shell"), Some("getprop"), _)
            | (Some("emu"), Some("avd"), Some("name"))
    )
}

/// Every script that starts an emulator on a serial of its own asks the device on that serial for its
/// name once the emulator has booted, and a device that is not KalaReach's has nothing installed
/// into it, set, driven or stopped: after the start the script's calls to the debug bridge only read.
/// The same machine with KalaReach's device on the serial goes on to install, and stops the device
/// when it ends.
#[test]
fn a_device_on_any_scripts_own_serial_that_is_not_kalareachs_is_left_alone() {
    let mut problems = Vec::new();
    for path in OWN_SERIAL {
        let script = SCRIPTS
            .iter()
            .find(|script| script.path == path)
            .expect("a script of the cases");
        let other = run_with(
            script,
            &[OTHERS[0], KALAREACH],
            None,
            &[],
            &Setup {
                boots_as: Some(OTHERS[0]),
                ..Setup::default()
            },
        );
        let mut wrong = Vec::new();
        if other.status == Some(0) {
            wrong.push("it ran to its end".to_string());
        }
        // The companion's own scripts stop with a line that does not name the device; the others say
        // which device answered.
        if path.starts_with("scripts/") && !other.output.contains(OTHERS[0]) {
            wrong.push(format!("it did not name {}", OTHERS[0]));
        }
        if other.started() != [KALAREACH] {
            wrong.push(format!("it started {:?}", other.started()));
        }
        let changes: Vec<&String> = other
            .calls
            .iter()
            .filter(|call| call.starts_with("adb ") && !only_reads(call))
            .collect();
        if !changes.is_empty() {
            wrong.push(format!("it went on with the other device: {changes:?}"));
        }
        if !wrong.is_empty() {
            problems.push(format!("{path}: {}\n{}", wrong.join(", "), other.output));
        }
        // What each script said, for whoever reads the run.
        println!(
            "{path}: status {:?}, {} calls to adb, all reads; it said: {}",
            other.status,
            other
                .calls
                .iter()
                .filter(|call| call.starts_with("adb "))
                .count(),
            other
                .output
                .lines()
                .find(|line| line.contains("left alone") || line.contains("is not the emulator"))
                .unwrap_or("")
        );

        if INSTALLS.contains(&path) {
            let own = run_with(
                script,
                &[OTHERS[0], KALAREACH],
                None,
                &[],
                &Setup {
                    boots_as: Some(KALAREACH),
                    installs_fail: true,
                    ..Setup::default()
                },
            );
            if !own.calling_contains("adb", "install") || !own.calling_contains("adb", "kill") {
                problems.push(format!(
                    "{path} with KalaReach's device did not install and stop it:\n{}\n{}",
                    own.output,
                    own.calls.join("\n")
                ));
            }
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// The driver moves the emulator's camera through its controller's port of the loopback interface, so
/// a port that already answers is some other program's and no emulator is started while it does.
#[test]
fn the_pairing_script_starts_no_emulator_while_its_controllers_port_is_taken() {
    let taken = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
    let port = taken.local_addr().expect("its address").port().to_string();
    let run = run(
        pairing_script(),
        &[KALAREACH],
        None,
        &[("KR_PAIRING_GRPC_PORT", &port)],
    );
    assert_eq!(run.status, Some(3), "{}", run.output);
    assert!(run.output.contains(&port), "{}", run.output);
    assert!(run.started().is_empty(), "{:?}", run.started());
    drop(taken);
}

/// What the pairing run writes may hold a phone's log with an invitation's secret in it: its folders
/// are for its owner alone and so is every file in them, whatever an earlier run left there.
#[test]
fn the_pairing_runs_output_is_for_its_owner_alone() {
    let run = run_with(
        pairing_script(),
        &[KALAREACH],
        None,
        &[],
        &Setup {
            readable_outputs: true,
            ..Setup::default()
        },
    );
    let mut problems = Vec::new();
    let mut files = 0;
    for folder in ["artefacts/pairing-device-android", "shots"] {
        let mut pending = vec![run.directory.path().join(folder)];
        while let Some(path) = pending.pop() {
            let mode = fs::metadata(&path)
                .expect("what the run left")
                .permissions()
                .mode()
                & 0o777;
            if path.is_dir() {
                if mode != 0o700 {
                    problems.push(format!("{} is {mode:o}", path.display()));
                }
                pending.extend(
                    fs::read_dir(&path)
                        .expect("a folder")
                        .map(|entry| entry.expect("an entry").path()),
                );
            } else {
                files += 1;
                if mode != 0o600 {
                    problems.push(format!("{} is {mode:o}", path.display()));
                }
            }
        }
    }
    // The earlier run's two files and what this run wrote are all read.
    assert!(files > 3, "the run left {files} files\n{}", run.output);
    assert!(
        problems.is_empty(),
        "{}\n{}",
        problems.join("\n"),
        run.output
    );
}

fn pairing_script() -> &'static Script {
    SCRIPTS
        .iter()
        .find(|script| script.path == "scripts/e2e-pairing-device.sh")
        .expect("the pairing script is among the scripts")
}

#[test]
fn an_emulator_that_is_already_running_is_used_only_when_it_is_kalareachs() {
    let listed = [OTHERS[0], KALAREACH];
    let mobile = &SCRIPTS[0];

    let other = run(mobile, &listed, Some(("emulator-5554", OTHERS[0])), &[]);
    assert_eq!(other.status, Some(3), "{}", other.output);
    assert!(other.output.contains("left alone"), "{}", other.output);
    // Nothing was forwarded into it, opened in it or photographed from it.
    for word in ["reverse", "start", "exec-out", "shell"] {
        assert!(
            !other.calling_contains("adb", word),
            "the script went on with another project's emulator ({word}):\n{}",
            other.calls.join("\n")
        );
    }
    assert!(other.started().is_empty());

    let own = run(mobile, &listed, Some(("emulator-5554", KALAREACH)), &[]);
    assert_eq!(own.status, Some(0), "{}", own.output);
    assert!(
        own.calling_contains("adb", "reverse"),
        "{}",
        own.calls.join("\n")
    );
    assert!(own.started().is_empty());
}

/// The text of every line of `source` that is not a comment.
fn code_lines(source: &str) -> impl Iterator<Item = &str> {
    source
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
}

fn shell_scripts(directory: &Path, found: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if entry.file_name() != "node_modules" {
                shell_scripts(&path, found);
            }
        } else if path.extension().is_some_and(|extension| extension == "sh") {
            found.push(path);
        }
    }
}

/// Whether `line` spells out a virtual device's name, such as `Name_API_36_Play`.
fn names_a_device(line: &str) -> bool {
    line.match_indices("_API_").any(|(at, marker)| {
        line[at + marker.len()..]
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_digit())
    })
}

/// A script may start a virtual device only if the cases above run it, and may not choose or list
/// one itself, so a new script cannot go back to another project's device without failing here.
#[test]
fn no_script_chooses_a_virtual_device_except_through_the_library() {
    let root = repository();
    let library = root.join("scripts/lib/android-avd.sh");
    let mut scripts = Vec::new();
    shell_scripts(&root.join("scripts"), &mut scripts);
    shell_scripts(&root.join("apps/companion/e2e"), &mut scripts);
    assert!(
        scripts.len() > 10,
        "the search found {} scripts",
        scripts.len()
    );

    let mut starting = Vec::new();
    for path in scripts.iter().filter(|path| **path != library) {
        let mut starts = false;
        let name = path
            .strip_prefix(&root)
            .expect("inside the tree")
            .to_string_lossy()
            .into_owned();
        let source = fs::read_to_string(path).expect("a script");
        for line in code_lines(&source) {
            for word in ["-list-avds", "KR_ANDROID_AVD", "avdmanager"] {
                assert!(
                    !line.contains(word),
                    "{name} chooses a virtual device itself ({word}): {line}"
                );
            }
            assert!(
                !names_a_device(line),
                "{name} names a virtual device itself: {line}"
            );
            // Every line is read, so a start added after the first one is read too.
            starts |= line.split_whitespace().any(|word| word == "-avd");
        }
        if starts {
            starting.push(name);
        }
    }

    let mut cases: Vec<&str> = SCRIPTS.iter().map(|script| script.path).collect();
    cases.sort_unstable();
    starting.sort_unstable();
    assert_eq!(
        starting, cases,
        "the scripts that start a virtual device are the ones the cases run"
    );
}

/// The wait for a case's jobs sees them: a process that has the case's directory in its command
/// line is still there when the wait has looked three times, and the wait returns only once the
/// process has gone. A wait whose pattern matches nothing returns at once and shows nothing, and
/// the record it then reads has not got the calls the job has yet to make.
#[test]
fn the_wait_for_the_jobs_of_a_case_sees_a_process_that_names_the_cases_directory() {
    let directory = TempDir::new().expect("a directory");
    let root = directory.path();
    let tools = root.join("tools");
    let record = root.join("record");
    let go = root.join("go");
    let marker = root.join("marker");
    // The look is the real one, and each look is a line of the record.
    stand_in(&tools, "pgrep", &record, "exec pgrep \"$@\"");
    // A job that goes on until it is let go, then does its work, and names the case's directory
    // only in its command line, as the jobs of a script do.
    // It also goes when the test that started it does, or after a minute in any case.
    let mut job = Command::new("/bin/sh")
        .args([
            "-c",
            "n=0; while [ ! -e \"$1\" ] && kill -0 \"$PPID\" 2>/dev/null && [ \"$n\" -lt 1200 ]; do \
             sleep 0.05; n=$((n + 1)); done; : > \"$2\"",
            "job",
        ])
        .arg(&go)
        .arg(&marker)
        .spawn()
        .expect("starts the job");
    let looks = || {
        fs::read_to_string(&record)
            .unwrap_or_default()
            .lines()
            .count()
    };
    let returned_while_the_job_ran = std::thread::scope(|scope| {
        let waiting =
            scope.spawn(|| until_nothing_runs_in(&tools.join("pgrep"), root, JOBS_END_WITHIN));
        // The job is let go when the wait has looked three times with the job running, or when the
        // wait has returned without having waited for it.
        while !waiting.is_finished() && looks() < 3 {
            std::thread::sleep(Duration::from_millis(20));
        }
        let early = waiting.is_finished();
        fs::write(&go, "").expect("lets the job go");
        (early, waiting.join())
    });
    let (returned_while_the_job_ran, waited) = returned_while_the_job_ran;
    let recorded = marker.exists();
    // The job is ended whatever the wait did, and collected, before the case goes on or fails.
    let _ = job.kill();
    let collected = collected_within(&mut job, Duration::from_secs(10));
    if let Err(payload) = waited {
        std::panic::resume_unwind(payload);
    }
    assert!(
        collected,
        "the job was still there 10 s after it was killed"
    );
    assert!(
        !returned_while_the_job_ran,
        "the wait returned before it had looked three times, with a process that names the case's \
         directory still running"
    );
    assert!(
        recorded,
        "the wait returned while a process that names the case's directory was still running"
    );
}

/// A look at the processes that never ends fails the case with the look named, in the time the
/// wait is given, where a wait for it would hold the suite for good.
#[test]
fn a_look_at_the_processes_that_never_ends_fails_the_case_and_names_the_look() {
    let directory = TempDir::new().expect("a directory");
    let tools = directory.path().join("tools");
    let record = directory.path().join("record");
    stand_in(&tools, "pgrep", &record, "exec sleep 600");
    let failed = std::panic::catch_unwind(|| {
        until_nothing_runs_in(
            &tools.join("pgrep"),
            directory.path(),
            Duration::from_secs(2),
        );
    });
    let panic = failed.expect_err("a look that never ends fails the case");
    let said = panic.downcast_ref::<String>().cloned().unwrap_or_default();
    assert!(
        said.contains("pgrep") && said.contains("did not end within"),
        "{said}"
    );
}

/// A child that does not go is reported within the time given, and not waited for.
#[test]
fn a_child_that_does_not_go_is_reported_within_the_time_given_and_not_waited_for() {
    let mut child = Command::new("/bin/sleep")
        .arg("300")
        .spawn()
        .expect("starts a child");
    let collected = collected_within(&mut child, Duration::from_millis(500));
    // Ended before anything is asserted, and collected within a time of its own: a child that does
    // not go is said to be there, and is not waited for.
    let _ = child.kill();
    let ended = collected_within(&mut child, Duration::from_secs(10));
    assert!(!collected, "a child that is still running is not collected");
    assert!(ended, "the child was still there 10 s after it was killed");
}

/// A command that ended while something it started still holds its output fails the case, naming
/// the command, where an empty answer would pass a case that read only the status.
///
/// What holds the output holds it until the case lets it go, which is after the command has failed,
/// so no delay in the machine can end it before the command has looked. The command has the time a
/// script is given to end, and only the wait for its streams is short; the case then waits for the
/// descendant to say that it has gone, so that none is left behind.
#[test]
fn a_command_that_ended_and_left_something_holding_its_output_fails_the_case() {
    let directory = TempDir::new().expect("a directory");
    let release = directory.path().join("release");
    let gone = directory.path().join("gone");
    let mut command = Command::new("/bin/sh");
    command
        .args([
            "-c",
            // The descendant ends when it is let go, or when this test process does, and says so.
            "( while [ ! -e \"$1\" ] && kill -0 \"$3\" 2>/dev/null; do sleep 0.1; done; : > \"$2\" ) \
             & exit 0",
            "program",
        ])
        .arg(&release)
        .arg(&gone)
        .arg(std::process::id().to_string());
    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        to_its_end_with_streams(command, SCRIPT_ENDS_WITHIN, Some(Duration::from_secs(1)))
    }));
    fs::write(&release, "").expect("lets the descendant go");
    let begun = Instant::now();
    while !gone.exists() && begun.elapsed() < Duration::from_secs(60) {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        gone.exists(),
        "the descendant did not end when it was let go"
    );
    let panic = failed.expect_err("output that is still held fails the case");
    let said = panic.downcast_ref::<String>().cloned().unwrap_or_default();
    assert!(
        said.contains("still holds its output") && said.contains("/bin/sh"),
        "{said}"
    );
}
