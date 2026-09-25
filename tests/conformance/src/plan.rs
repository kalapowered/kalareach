//! What the report runs, on each platform, and what it reads besides the tests' own comments.
//!
//! The report runs five groups. Each is a list of steps, and each step is a command the report
//! runs as it is written here and records verbatim in the result:
//!
//! * `rust`: the workspace's tests, as the landing workflow runs them on this platform. On Linux
//!   that is the whole workspace. On macOS it is the same command with the cases this platform's
//!   runner cannot host left out by name, each with its reason, and the timed cases run one at a
//!   time. On Windows it is the suites qualified there, one command each.
//! * `end-to-end`: the suites `scripts/end-to-end.sh` runs, with the flags it runs them with.
//! * `performance`: the measurements `scripts/performance.sh` takes and the two release-build
//!   throughput and scheduling suites, with the flags the landing workflow runs them with.
//! * `typescript`: each package's own `test` script, reporting in JSON.
//! * `applications`: the application matrix, over the programs the fetch step installed.
//!
//! A test that none of the selected groups runs on this platform is reported as not run, with the
//! reason this plan gives, and never as passed.

use crate::id::Identifier;

/// One group of steps.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Group {
    /// The workspace's Rust tests.
    Rust,
    /// The end-to-end suites.
    EndToEnd,
    /// The performance measurements.
    Performance,
    /// The TypeScript packages' tests.
    TypeScript,
    /// The application matrix.
    Applications,
}

impl Group {
    /// Every group, in the order a full run runs them.
    pub const ALL: [Self; 5] = [
        Self::Rust,
        Self::EndToEnd,
        Self::Performance,
        Self::TypeScript,
        Self::Applications,
    ];

    /// The name a selection gives it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Rust => "rust",
            Self::EndToEnd => "end-to-end",
            Self::Performance => "performance",
            Self::TypeScript => "typescript",
            Self::Applications => "applications",
        }
    }

    /// The group a selection names.
    #[must_use]
    pub fn named(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|group| group.name() == name)
    }
}

/// The platforms the report knows how to run on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Platform {
    /// Linux.
    Linux,
    /// macOS.
    MacOs,
    /// Windows.
    Windows,
}

impl Platform {
    /// The platform this binary was built for.
    #[must_use]
    pub const fn current() -> Self {
        if cfg!(target_os = "macos") {
            Self::MacOs
        } else if cfg!(windows) {
            Self::Windows
        } else {
            Self::Linux
        }
    }

    /// Its name in the result.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::MacOs => "macos",
            Self::Windows => "windows",
        }
    }
}

/// How a step's output is read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reading {
    /// `cargo test` output: one or more test binaries, each announced by Cargo.
    Cargo,
    /// A build whose success is all there is to record.
    Build,
    /// A package's `test` script, reporting to the JSON file named, for the package in the
    /// directory named.
    Vitest {
        /// The package's directory, relative to the repository.
        directory: String,
    },
}

/// One command of a group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step {
    /// Its group.
    pub group: Group,
    /// What it runs, in a few words.
    pub what: String,
    /// The program and its arguments, as run.
    pub command: Vec<String>,
    /// Variables it reads from the environment the report was started in, which must be set.
    pub needs: Vec<&'static str>,
    /// How its output is read.
    pub reading: Reading,
    /// A name filter the command passes to the test binaries, and why tests outside it are not
    /// run on this platform.
    pub filter: Option<(String, String)>,
    /// Tests the command leaves out by name, each with its reason.
    pub skips: Vec<(String, String)>,
}

impl Step {
    /// A `cargo` command of `group`, described as `what`.
    ///
    /// A `cargo test` that leaves each test's output captured is given `--show-output`, which
    /// prints what every test that passed wrote, under its name: that is where a test that returned
    /// early says so, and where the report reads it. One that shows the output as it is written,
    /// with `--nocapture`, is left as it is.
    #[must_use]
    pub fn cargo(group: Group, what: &str, arguments: &[&str]) -> Self {
        let mut command = vec!["cargo".to_owned()];
        command.extend(arguments.iter().map(|argument| (*argument).to_owned()));
        if arguments.first() == Some(&"test") && !arguments.contains(&"--nocapture") {
            if !arguments.contains(&"--") {
                command.push("--".to_owned());
            }
            command.push("--show-output".to_owned());
        }
        Self {
            group,
            what: what.to_owned(),
            command,
            needs: Vec::new(),
            reading: Reading::Cargo,
            filter: None,
            skips: Vec::new(),
        }
    }

    fn filtered(mut self, filter: &str, reason: &str) -> Self {
        self.filter = Some((filter.to_owned(), reason.to_owned()));
        self
    }

    fn skipping(mut self, skips: &[(&str, &str)]) -> Self {
        let separator = self.command.iter().any(|argument| argument == "--");
        if !separator {
            self.command.push("--".to_owned());
        }
        for (name, reason) in skips {
            self.command.push("--skip".to_owned());
            self.command.push((*name).to_owned());
            self.skips.push(((*name).to_owned(), (*reason).to_owned()));
        }
        self
    }

    /// The command as one line, the way the result records it.
    #[must_use]
    pub fn line(&self) -> String {
        self.command
            .iter()
            .map(|word| quote(word))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// Quotes a word for a POSIX shell only when it needs it.
#[must_use]
pub fn quote(word: &str) -> String {
    if !word.is_empty()
        && word
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_./:=,@+%".contains(&b))
    {
        word.to_owned()
    } else {
        format!("'{}'", word.replace('\'', "'\\''"))
    }
}

/// The suites `scripts/end-to-end.sh` runs, as package and test target, in its order. The
/// report's own tests check this list against the script.
pub const END_TO_END_SUITES: &[(&str, &str)] = &[
    ("kr-worker", "host"),
    ("kr-worker", "terminal"),
    ("kr-worker", "authority"),
    ("kr-worker", "receipts"),
    ("kr-controller", "barrier"),
    ("kr-worker", "backpressure"),
    ("kr-worker", "session"),
    ("kr-worker", "fence"),
    ("kr-controller", "shell"),
    ("kr-controller", "contracts"),
    ("kr-controller", "envelope"),
    ("kr-controller", "project"),
    ("kr-controller", "voice"),
    ("kr-controller", "changeset"),
    ("kr-cli", "attach"),
    ("kr-cli", "lifecycle"),
    ("kr-controller", "network"),
];

/// The measurements `scripts/performance.sh` takes: the target (`test` or `bench`) of kr-worker
/// each is in, and its name. The report's own tests check this list against the script.
pub const MEASUREMENTS: &[(&str, &str)] = &[
    ("test performance", "attach_to_a_usable_screen"),
    ("bench input_latency", "added_input_forwarding_latency"),
    ("bench input_latency", "paste_prefix_recogniser_deadline"),
    (
        "test performance",
        "idle_resources_for_twenty_sessions_and_thirty_two_views",
    ),
];

/// The TypeScript packages, by directory.
pub const TYPESCRIPT_PACKAGES: &[&str] =
    &["packages/protocol", "packages/plugin-sdk", "apps/companion"];

/// The cases the macOS runner leaves out of the workspace run, each with its reason.
const MACOS_SKIPS: &[(&str, &str)] = &[
    (
        "the_helper_inside_a_container_refuses_a_handshake_that_declares_a_network_actor",
        "needs podman, which the macOS runner does not have; the Linux run hosts it",
    ),
    (
        "a_running_container_is_observed_as_running_and_a_stopped_one_as_stopped",
        "needs podman, which the macOS runner does not have; the Linux run hosts it",
    ),
    (
        "a_reused_container_name_is_not_the_identity_that_was_enrolled",
        "needs podman, which the macOS runner does not have; the Linux run hosts it",
    ),
    (
        "the_argument_vector_reaches_the_container_exactly_as_it_was_built",
        "needs podman, which the macOS runner does not have; the Linux run hosts it",
    ),
    (
        "a_helper_path_with_a_space_in_it_is_one_argument_inside_the_container",
        "needs podman, which the macOS runner does not have; the Linux run hosts it",
    ),
    (
        "a_refresh_that_reached_a_running_environment_without_a_helper_scopes_no_channel",
        "needs podman, which the macOS runner does not have; the Linux run hosts it",
    ),
    (
        "a_key_kept_in_the_platform_store_is_read_back_from_it_and_taken_away_again",
        "writes the platform's credential store, which the landing workflow's companion job does with its switch set",
    ),
    (
        "the_built_packages_are_qualified_where_this_run_has_them",
        "launches a built shell package, and this run builds none; the landing workflow's shell-packages job builds them and drives them",
    ),
    (
        "a_real_qualified_package_registers_and_qualifies_on_this_hosts_endpoint",
        "launches a built shell package, and this run builds none; the landing workflow's shell-packages job builds them and drives them",
    ),
    (
        "a_repository_whose_own_data_is_on_another_filesystem_is_captured",
        "needs a second filesystem, which the landing workflow's macOS job attaches for it",
    ),
    (
        "bind_mount_and_cross_device_grafts_are_refused",
        "needs a second filesystem, which the landing workflow's macOS job attaches for it",
    ),
    (
        "recursive_removal_refuses_a_grafted_mount",
        "needs a second filesystem, which the landing workflow's macOS job attaches for it",
    ),
    (
        "a_removal_stops_before_a_disk_image_attached_inside_the_tree",
        "needs a second filesystem, which the landing workflow's macOS job attaches for it",
    ),
    (
        "kr_req_11_38_every_export_is_stopped_by_its_own_deadline",
        "a timed case, which runs in a step of its own, one at a time",
    ),
    (
        "kr_req_11_38_a_worker_is_told_when_the_queue_overflowed",
        "a timed case, which runs in a step of its own, one at a time",
    ),
];

/// Why a package no macOS step runs is left out there.
pub const MACOS_EXCLUDED: &[(&str, &str)] = &[(
    "kr-sync-integration",
    "every test of this package is a leg against a live deployment; the Linux run takes each leg against the deployment it names",
)];

/// Why a test no step runs on this platform is not run, when the platform says why in general.
#[must_use]
pub const fn unrun_reason(platform: Platform) -> &'static str {
    match platform {
        Platform::Windows => {
            "no step runs this target on Windows: the suites that drive a Unix pseudo-terminal are compiled there and qualified on Unix, and the pseudo-console is qualified on the Windows test machine"
        }
        Platform::Linux | Platform::MacOs => {
            "no step of this run's selection runs this target on this platform"
        }
    }
}

/// Every step the selected groups run on `platform`.
///
/// `evidence` is the directory the vitest reports are written into, and `applications` names the
/// programs whose cases are left out, each with its reason.
#[must_use]
pub fn steps(
    platform: Platform,
    groups: &[Group],
    evidence: &str,
    applications: Option<&ApplicationsPlan>,
) -> Vec<Step> {
    let mut steps = Vec::new();
    for group in Group::ALL
        .into_iter()
        .filter(|group| groups.contains(group))
    {
        match group {
            Group::Rust => steps.extend(rust(platform)),
            Group::EndToEnd if platform != Platform::Windows => {
                steps.push(Step {
                    reading: Reading::Build,
                    ..Step::cargo(
                        Group::EndToEnd,
                        "the worker the network suite launches",
                        &["build", "--locked", "-p", "kr-worker", "--bin", "kr-worker"],
                    )
                });
                for (package, suite) in END_TO_END_SUITES {
                    let mut arguments = vec![
                        "test",
                        "--locked",
                        "-p",
                        package,
                        "--test",
                        suite,
                        "--",
                        "--test-threads=1",
                    ];
                    if *suite == "network" {
                        arguments.push("--include-ignored");
                    }
                    steps.push(Step::cargo(
                        Group::EndToEnd,
                        &format!("{package} {suite}, one test at a time"),
                        &arguments,
                    ));
                }
            }
            Group::Performance if platform != Platform::Windows => {
                steps.push(Step::cargo(
                    Group::Performance,
                    "the measurement suite's own regressions",
                    &[
                        "test",
                        "--locked",
                        "--release",
                        "-p",
                        "kr-worker",
                        "--test",
                        "performance",
                    ],
                ));
                steps.push(Step::cargo(
                    Group::Performance,
                    "the input measurements' own regressions",
                    &[
                        "test",
                        "--locked",
                        "--release",
                        "-p",
                        "kr-worker",
                        "--bench",
                        "input_latency",
                    ],
                ));
                for (target, name) in MEASUREMENTS {
                    let (kind, target) = target.split_once(' ').unwrap_or(("test", target));
                    steps.push(Step::cargo(
                        Group::Performance,
                        &format!("the {name} measurement"),
                        &[
                            "test",
                            "--locked",
                            "--release",
                            "-p",
                            "kr-worker",
                            &format!("--{kind}"),
                            target,
                            "--",
                            "--ignored",
                            "--exact",
                            "--nocapture",
                            name,
                        ],
                    ));
                }
                steps.push(Step::cargo(
                    Group::Performance,
                    "terminal output handling, optimised",
                    &[
                        "test",
                        "--locked",
                        "--release",
                        "-p",
                        "kr-term",
                        "--test",
                        "perf",
                        "--",
                        "--nocapture",
                        "--test-threads=1",
                    ],
                ));
                steps.push(Step::cargo(
                    Group::Performance,
                    "transport scheduling and reconnect, optimised",
                    &[
                        "test",
                        "--locked",
                        "--release",
                        "-p",
                        "kr-transport",
                        "--test",
                        "perf",
                        "--",
                        "--nocapture",
                        "--test-threads=1",
                    ],
                ));
            }
            Group::TypeScript if platform != Platform::Windows => {
                // The report's own reading of TypeScript, over its fixture: it needs the compiler
                // the packages install, which this group has.
                steps.push(Step::cargo(
                    Group::TypeScript,
                    "the report's own reading of TypeScript",
                    &[
                        "test",
                        "--locked",
                        "-p",
                        "kr-conformance",
                        "--test",
                        "report",
                        "--",
                        "--ignored",
                        "--exact",
                        "typescript_comment_forms_and_titles_key_their_tests",
                    ],
                ));
                for directory in TYPESCRIPT_PACKAGES {
                    let report = format!(
                        "{evidence}/conformance/vitest/{}.json",
                        directory.replace('/', "-")
                    );
                    steps.push(Step {
                        group: Group::TypeScript,
                        what: format!("{directory}'s tests"),
                        command: vec![
                            "pnpm".to_owned(),
                            "--dir".to_owned(),
                            (*directory).to_owned(),
                            "run".to_owned(),
                            "test".to_owned(),
                            "--reporter=default".to_owned(),
                            "--reporter=json".to_owned(),
                            format!("--outputFile.json={report}"),
                            "--includeTaskLocation".to_owned(),
                        ],
                        needs: Vec::new(),
                        reading: Reading::Vitest {
                            directory: (*directory).to_owned(),
                        },
                        filter: None,
                        skips: Vec::new(),
                    });
                }
            }
            Group::Applications if platform != Platform::Windows => {
                if let Some(plan) = applications {
                    let mut step = Step::cargo(
                        Group::Applications,
                        "the application matrix in a real session",
                        &[
                            "test",
                            "--locked",
                            "-p",
                            "kr-conformance",
                            "--test",
                            "applications",
                            "--",
                            "--ignored",
                            "--test-threads=1",
                        ],
                    );
                    step.needs.push(APPLICATIONS_VARIABLE);
                    let skips: Vec<(String, String)> = plan
                        .left_out
                        .iter()
                        .map(|(id, reason)| (format!("{id}::"), reason.clone()))
                        .collect();
                    for (prefix, reason) in &skips {
                        step.command.push("--skip".to_owned());
                        step.command.push(prefix.clone());
                        step.skips.push((prefix.clone(), reason.clone()));
                    }
                    steps.push(step);
                }
            }
            _ => {}
        }
    }
    steps
}

/// The variable naming the cache the fetch step installed the applications into.
pub const APPLICATIONS_VARIABLE: &str = "KR_CONFORMANCE_APPLICATIONS";

/// The programs whose cases a run leaves out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplicationsPlan {
    /// Each program with no build installed here, and why.
    pub left_out: Vec<(String, String)>,
}

fn rust(platform: Platform) -> Vec<Step> {
    match platform {
        Platform::Linux => vec![Step::cargo(
            Group::Rust,
            "the workspace's tests",
            &["test", "--locked", "--workspace", "--no-fail-fast"],
        )],
        Platform::MacOs => vec![
            Step::cargo(
                Group::Rust,
                "the workspace's tests, less what the macOS runner cannot host",
                &[
                    "test",
                    "--locked",
                    "--workspace",
                    "--exclude",
                    "kr-sync-integration",
                    "--no-fail-fast",
                ],
            )
            .skipping(MACOS_SKIPS),
            Step::cargo(
                Group::Rust,
                "the timed cases, one at a time",
                &[
                    "test",
                    "--locked",
                    "--workspace",
                    "--exclude",
                    "kr-sync-integration",
                    "--no-fail-fast",
                    "--test",
                    "service",
                    "--test",
                    "execution",
                    "--",
                    "--exact",
                    "--test-threads=1",
                    "kr_req_11_38_a_worker_is_told_when_the_queue_overflowed",
                    "kr_req_11_38_every_export_is_stopped_by_its_own_deadline",
                ],
            )
            .filtered(
                "kr_req_11_38_",
                "this step runs only the two timed cases; the step before it runs the rest",
            ),
        ],
        Platform::Windows => windows(),
    }
}

fn windows() -> Vec<Step> {
    let only = |filter: &str| {
        (
            filter.to_owned(),
            format!("on Windows only the cases named `{filter}` of this target are qualified"),
        )
    };
    let mut steps = vec![
        Step::cargo(
            Group::Rust,
            "the terminal engine, the repository boundary and the attach client",
            &["test", "--locked", "-p", "kr-term", "-p", "kr-project", "-p", "kr-cli"],
        ),
        Step::cargo(Group::Rust, "the worker's library", &["test", "--locked", "-p", "kr-worker", "--lib"]),
        Step::cargo(Group::Rust, "the settings-sync store", &["test", "--locked", "-p", "kr-client", "--test", "sync"]),
        Step::cargo(
            Group::Rust,
            "a pseudo-console, PowerShell and the session job object",
            &["test", "--locked", "-p", "kr-worker", "--test", "windows"],
        ),
        Step::cargo(
            Group::Rust,
            "a launched agent's helper placed by its job",
            &["test", "--locked", "-p", "kr-worker", "--test", "question_bindings"],
        ),
        Step::cargo(
            Group::Rust,
            "the local endpoint, the descriptors and the process identity",
            &["test", "--locked", "-p", "kr-ipc", "--test", "windows"],
        ),
        Step::cargo(Group::Rust, "the local IPC library", &["test", "--locked", "-p", "kr-ipc", "--lib"]).skipping(&[
            (
                "framed::tests::a_checked_write_asks_before_every_transport_write",
                "not qualified on Windows's named pipes",
            ),
            (
                "framed::tests::a_peer_that_stops_reading_blocks_the_attempt_rather_than_holding_the_writer",
                "not qualified on Windows's named pipes",
            ),
        ]),
        Step::cargo(
            Group::Rust,
            "what a question's caller token reaches",
            &["test", "--locked", "-p", "kr-worker", "--test", "questions_answer"],
        ),
        Step::cargo(
            Group::Rust,
            "controller and local authority at a worker's pipe",
            &["test", "--locked", "-p", "kr-worker", "--test", "authority"],
        ),
        Step::cargo(Group::Rust, "the attention store", &["test", "--locked", "-p", "kr-attention"]),
        Step::cargo(
            Group::Rust,
            "the PowerShell bridge client over a named pipe",
            &["test", "--locked", "-p", "kr-shell-integration", "--test", "pwsh_windows"],
        ),
        // The landing workflow runs these three with `--nocapture`, so that a case that could not
        // build what it needs says so; `--show-output` prints the same, under each test's name.
        Step::cargo(
            Group::Rust,
            "the repository boundary",
            &["test", "--locked", "-p", "kr-project", "--test", "boundary"],
        ),
        Step::cargo(
            Group::Rust,
            "what an apply carries across",
            &["test", "--locked", "-p", "kr-changeset", "--test", "apply"],
        ),
        Step::cargo(
            Group::Rust,
            "filesystem authority and access-control lists",
            &["test", "--locked", "-p", "kr-transfer", "--lib", "--test", "authority"],
        ),
        // The one case that writes this machine's credential store runs only where the run was
        // started with KR_TEST_PLATFORM_SECRET_STORE=1, as the conformance workflow's runner is;
        // anywhere else it says it did nothing and is not run.
        Step::cargo(
            Group::Rust,
            "a collection key kept in this machine's credential store",
            &[
                "test",
                "--locked",
                "-p",
                "kr-client",
                "--lib",
                "--",
                "--exact",
                "sync::keys::tests::a_key_kept_in_the_platform_store_is_read_back_from_it_and_taken_away_again",
            ],
        ),
    ];
    let mut registry = Step::cargo(
        Group::Rust,
        "the registry's records of a previous release's workers",
        &[
            "test",
            "--locked",
            "-p",
            "kr-controller",
            "--lib",
            "registry",
        ],
    );
    registry.filter = Some(only("registry"));
    let mut store = Step::cargo(
        Group::Rust,
        "the settings-sync store's directory flush",
        &[
            "test",
            "--locked",
            "-p",
            "kr-client",
            "--lib",
            "sync::store",
        ],
    );
    store.filter = Some(only("sync::store"));
    let mut scripted = Step::cargo(
        Group::Rust,
        "the reference bridge over a real endpoint",
        &[
            "test",
            "--locked",
            "-p",
            "kr-shell-integration",
            "--lib",
            "host::scripted::",
        ],
    );
    scripted.filter = Some(only("host::scripted::"));
    steps.extend([registry, store, scripted]);
    steps
}

/// Why a group runs nothing on `platform`, where it does not.
#[must_use]
pub const fn group_absent_reason(group: Group, platform: Platform) -> Option<&'static str> {
    match (group, platform) {
        (Group::EndToEnd | Group::Performance, Platform::Windows) => Some(
            "the end-to-end suites and the measurements drive Unix pseudo-terminals; on Windows the pseudo-console is qualified on the Windows test machine",
        ),
        (Group::TypeScript, Platform::Windows) => {
            Some("the TypeScript suites are qualified on Linux and macOS")
        }
        (Group::Applications, Platform::Windows) => Some(
            "a console application on Windows is driven through the pseudo-console, which the Windows test machine qualifies",
        ),
        _ => None,
    }
}

/// A data file of cases that names the rows it covers, and the tests that run its cases.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CaseTable {
    /// The files, relative to the repository: `*` stands for one path component.
    pub files: &'static str,
    /// The package whose tests run them.
    pub package: &'static str,
    /// The test target.
    pub target: &'static str,
    /// The tests, by name.
    pub tests: &'static [&'static str],
}

/// The case tables kept as data files. A `const` or `static` case table in Rust needs no entry:
/// its consumers are the tests that name it.
pub const CASE_TABLES: &[CaseTable] = &[
    CaseTable {
        files: "tests/shells/*/*/case.json",
        package: "kr-shell-integration",
        target: "qualification",
        tests: &["every_case_holds_against_the_package_it_names"],
    },
    CaseTable {
        files: "fixtures/shell-bridge/*.json",
        package: "kr-shell-integration",
        target: "harness",
        tests: &["every_committed_scenario_holds_against_the_contract"],
    },
];

/// A set of files whose tests another toolchain builds, which the report reads the keys of and
/// does not run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lane {
    /// The files, relative to the repository: `*` stands for one path component and `**` for any
    /// number of them.
    pub files: &'static str,
    /// Why the report does not build them.
    pub reason: &'static str,
}

/// The lanes.
pub const LANES: &[Lane] = &[
    Lane {
        files: "apps/companion/native/android/src/test/**",
        reason: "Android unit tests: the Android build runs them",
    },
    Lane {
        files: "apps/companion/native/ios/Tests/**",
        reason: "iOS unit tests: Xcode runs them",
    },
    Lane {
        files: "apps/companion/e2e/**",
        reason: "Playwright over the built interface: `pnpm --dir apps/companion run e2e` runs it, in the landing workflow's companion job",
    },
];

/// Section 27's terminal conformance matrix.
pub const TERMINALS: &[&str] = &[
    "iTerm2",
    "Terminal.app",
    "Ghostty",
    "WezTerm",
    "Windows Terminal",
    "a VTE-based Linux terminal",
    "the VS Code terminal",
];

/// Why a terminal of the matrix is not run by this report.
pub const TERMINAL_REASON: &str = "the physical terminal matrix runs on the terminal matrix hosts and virtual machines; this run recorded no run of it";

/// Whether `path` matches a pattern of `*` (one component) and `**` (any number).
#[must_use]
pub fn matches(pattern: &str, path: &str) -> bool {
    fn walk(pattern: &[&str], path: &[&str]) -> bool {
        match (pattern.first(), path.first()) {
            (None, None) => true,
            (Some(&"**"), _) => {
                walk(&pattern[1..], path) || (!path.is_empty() && walk(pattern, &path[1..]))
            }
            (Some(want), Some(have)) => component(want, have) && walk(&pattern[1..], &path[1..]),
            _ => false,
        }
    }
    fn component(want: &str, have: &str) -> bool {
        match want.split_once('*') {
            None => want == have,
            Some((prefix, suffix)) => {
                have.len() >= prefix.len() + suffix.len()
                    && have.starts_with(prefix)
                    && have.ends_with(suffix)
            }
        }
    }
    let pattern: Vec<&str> = pattern.split('/').collect();
    let path: Vec<&str> = path.split('/').collect();
    walk(&pattern, &path)
}

/// The identifiers the report lists in every full run, whether or not a test names them.
#[must_use]
pub fn listed_rows() -> Vec<Identifier> {
    Identifier::table_rows()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pattern_matches_one_component_per_star_and_any_number_per_double_star() {
        assert!(matches(
            "tests/shells/*/*/case.json",
            "tests/shells/zsh/fzf/case.json"
        ));
        assert!(!matches(
            "tests/shells/*/*/case.json",
            "tests/shells/zsh/case.json"
        ));
        assert!(matches(
            "fixtures/shell-bridge/*.json",
            "fixtures/shell-bridge/handshake-accept.json"
        ));
        assert!(matches(
            "apps/companion/e2e/**",
            "apps/companion/e2e/companion.spec.ts"
        ));
        assert!(matches(
            "apps/companion/native/ios/Tests/**",
            "apps/companion/native/ios/Tests/a/b.swift"
        ));
        assert!(!matches(
            "apps/companion/e2e/**",
            "apps/companion/test/a.ts"
        ));
    }

    #[test]
    fn a_word_is_quoted_only_when_a_shell_would_split_it() {
        assert_eq!(quote("--test-threads=1"), "--test-threads=1");
        assert_eq!(quote("host::scripted::"), "host::scripted::");
        assert_eq!(quote("a b"), "'a b'");
        assert_eq!(quote("it's"), "'it'\\''s'");
    }

    #[test]
    fn every_platform_runs_the_rust_group_and_windows_runs_no_unix_group() {
        for platform in [Platform::Linux, Platform::MacOs, Platform::Windows] {
            let steps = steps(platform, &Group::ALL, "/tmp/e", None);
            assert!(
                steps.iter().any(|step| step.group == Group::Rust),
                "{platform:?}"
            );
            let unix_only = steps.iter().any(|step| {
                matches!(
                    step.group,
                    Group::EndToEnd | Group::Performance | Group::TypeScript
                )
            });
            assert_eq!(unix_only, platform != Platform::Windows, "{platform:?}");
        }
    }

    #[test]
    fn a_skipped_case_is_left_out_by_the_command_and_recorded_with_its_reason() {
        let steps = steps(Platform::MacOs, &[Group::Rust], "/tmp/e", None);
        let first = &steps[0];
        assert_eq!(first.skips.len(), MACOS_SKIPS.len());
        assert_eq!(
            first
                .command
                .iter()
                .filter(|word| *word == "--skip")
                .count(),
            MACOS_SKIPS.len()
        );
    }

    #[test]
    fn a_test_step_shows_what_its_passing_tests_wrote_unless_it_shows_it_as_written() {
        let line = |arguments: &[&str]| Step::cargo(Group::Rust, "x", arguments).line();
        assert_eq!(
            line(&["test", "--locked", "--workspace"]),
            "cargo test --locked --workspace -- --show-output"
        );
        assert_eq!(
            line(&["test", "-p", "a", "--", "--test-threads=1"]),
            "cargo test -p a -- --test-threads=1 --show-output"
        );
        assert_eq!(
            line(&["test", "-p", "a", "--", "--nocapture"]),
            "cargo test -p a -- --nocapture"
        );
        assert_eq!(line(&["build", "-p", "a"]), "cargo build -p a");
    }

    #[test]
    fn the_applications_left_out_are_skipped_by_prefix() {
        let plan = ApplicationsPlan {
            left_out: vec![("htop".to_owned(), "no build for this platform".to_owned())],
        };
        let steps = steps(
            Platform::Linux,
            &[Group::Applications],
            "/tmp/e",
            Some(&plan),
        );
        assert_eq!(steps.len(), 1);
        assert!(
            steps[0].line().ends_with("--skip htop::"),
            "{}",
            steps[0].line()
        );
        assert!(steps[0].line().starts_with("cargo test"));
        assert_eq!(steps[0].needs, [APPLICATIONS_VARIABLE]);
    }

    #[test]
    fn every_group_is_named_as_a_selection_names_it() {
        for group in Group::ALL {
            assert_eq!(Group::named(group.name()), Some(group));
        }
        assert_eq!(Group::named("terminals"), None);
    }
}
