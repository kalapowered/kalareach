//! The device scripts start KalaReach's own Android virtual device and no other.
//!
//! Every other virtual device on a machine belongs to other work, so a script that takes the first
//! one listed, or defaults to a name that is someone else's, starts, fills and wipes what is not
//! KalaReach's. Each case runs a script as it is committed, from a copy of the tree, with the
//! Android tools replaced by programs that record their arguments and start nothing: the SDK's
//! `adb` and `emulator`, and the build tools, browser and image reader a script calls before it
//! reaches the device. Every script is run to the point where it starts the emulator, so the
//! arguments the emulator was given are what the cases read.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

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
}

const SCRIPTS: [Script; 7] = [
    Script {
        path: "scripts/e2e-mobile.sh",
        args: &["android"],
        waits_for_boot: true,
    },
    Script {
        path: "scripts/e2e-voice-device.sh",
        args: &["android"],
        waits_for_boot: false,
    },
    Script {
        path: "scripts/e2e-voice-call-bridge.sh",
        args: &["android"],
        waits_for_boot: false,
    },
    Script {
        path: "scripts/e2e-voice-call-device.sh",
        args: &["android"],
        waits_for_boot: false,
    },
    Script {
        path: "apps/companion/e2e/android-stores.sh",
        args: &["application.apk"],
        waits_for_boot: false,
    },
    Script {
        path: "apps/companion/e2e/standing-emulator.sh",
        args: &[],
        waits_for_boot: false,
    },
    Script {
        path: "apps/companion/e2e/system-text-size-android.sh",
        args: &["application.apk"],
        waits_for_boot: false,
    },
];

/// What a run of a script said and asked of the tools.
struct Run {
    output: String,
    status: Option<i32>,
    /// Every call to a stand-in, in order, one line each: the program, then its arguments.
    calls: Vec<String>,
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
fn stand_in(directory: &Path, name: &str, record: &Path, body: &str) {
    let path = directory.join(name);
    fs::create_dir_all(directory).expect("a directory");
    fs::write(
        &path,
        format!(
            "#!/bin/sh\necho \"{name} $*\" >>\"{}\"\n{body}\n",
            record.display()
        ),
    )
    .expect("a stand-in");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("executable");
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

/// Runs `script` from a copy of the tree on a machine whose emulator lists `listed`, with the
/// virtual device `running` (an emulator serial and the name of its device) already up, if any.
fn run(
    script: &Script,
    listed: &[&str],
    running: Option<(&str, &str)>,
    extra: &[(&str, &str)],
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

    fs::write(root.join("avds.txt"), format!("{}\n", listed.join("\n"))).expect("a list");
    if let Some((serial, name)) = running {
        fs::write(root.join("running.txt"), format!("{serial}\tdevice\n")).expect("a device");
        fs::write(root.join("running-avd.txt"), format!("{name}\n")).expect("a name");
    }
    if script.waits_for_boot {
        fs::write(root.join("booted"), "").expect("a flag");
    }

    // The SDK's two programs. The emulator lists what the machine has and, asked to start a
    // device, only records it. The debug bridge reports the running emulator and its device, and
    // says the boot is complete only where a script waits for that.
    stand_in(
        &sdk.join("emulator"),
        "emulator",
        &record,
        &format!(
            "[ \"$1\" = -list-avds ] && cat \"{}\"\nexit 0",
            root.join("avds.txt").display()
        ),
    );
    stand_in(
        &sdk.join("platform-tools"),
        "adb",
        &record,
        &format!(
            "case \"$*\" in\n\
             *'emu avd name'*) [ -f \"{running_avd}\" ] && {{ cat \"{running_avd}\"; echo OK; }} ;;\n\
             *getprop*sys.boot_completed*) [ -f \"{booted}\" ] && echo 1 ;;\n\
             *getprop*) echo stand-in ;;\n\
             devices*) echo 'List of devices attached'; [ -f \"{running}\" ] && cat \"{running}\" ;;\n\
             esac\nexit 0",
            running_avd = root.join("running-avd.txt").display(),
            booted = root.join("booted").display(),
            running = root.join("running.txt").display(),
        ),
    );

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
             *--message-format=json*) echo '{{\"reason\":\"compiler-artifact\",\"executable\":\"{}\",\"target\":{{\"name\":\"voice_device\"}}}}' ;;\n\
             *) exit 1 ;;\n\
             esac",
            tools.join("voice_device").display()
        ),
    );
    stand_in(
        &tools,
        "node",
        &record,
        "if [ \"$1\" = scripts/preview-harness.mjs ]; then\n\
         while kill -0 \"$3\" 2>/dev/null; do sleep 0.2; done\nexit 0\nfi\nexit 1",
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
        .env("KR_STANDING_SHOTS", root.join("scratch"))
        .env("KR_TEXT_SIZE_SHOTS", root.join("scratch"))
        .env("KR_MOBILE_SETTLE", "0");
    for (name, value) in extra {
        command.env(name, value);
    }
    let output = command.output().expect("the script runs");
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    let calls = fs::read_to_string(&record)
        .expect("the record")
        .lines()
        .map(str::to_string)
        .collect();
    Run {
        output: text,
        status: output.status.code(),
        calls,
    }
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
        // A refusal costs the two voice-call scripts, which build the application (and one of them
        // the host), no build.
        if run.called("pnpm android") || run.called("cargo") {
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

#[test]
fn another_virtual_device_made_for_kalareach_is_named_in_the_environment() {
    let listed = [OTHERS[0], "KalaReach_API_36_Tablet", KALAREACH];
    let run = run(
        &SCRIPTS[0],
        &listed,
        None,
        &[("KR_ANDROID_AVD", "KalaReach_API_36_Tablet")],
    );
    assert_eq!(run.started(), ["KalaReach_API_36_Tablet"], "{}", run.output);

    // A name that is not listed is refused by name, and the default is not put in its place.
    let run = self::run(
        &SCRIPTS[0],
        &listed,
        None,
        &[("KR_ANDROID_AVD", "Missing_API_36")],
    );
    assert!(run.output.contains("Missing_API_36"), "{}", run.output);
    assert!(run.started().is_empty(), "{:?}", run.started());
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
