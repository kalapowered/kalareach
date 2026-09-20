//! The qualification matrix, and what has and has not actually been run.
//!
//! Section 22 ends with a list of fourteen things qualification covers *on all required host
//! architectures*, and one sentence about evidence somebody else supplied: *the supplied 13
//! September smoke results are preserved as reported, not independently reproduced [...] they do
//! not qualify the fallback or reference-host targets; the original benchmark scripts/raw outputs
//! were not supplied*.
//!
//! So this module is a record rather than a runner. It names every case, every target, and for each
//! pair what kind of evidence exists - a test in this repository, a benchmark run, a report nobody
//! reproduced, or nothing at all with an owner named. A matrix that only listed the cases that
//! passed would be the thing section 22 is guarding against.
//!
//! # What this build's evidence is
//!
//! [`Matrix::builtin`] is the state of the matrix in this repository. Every case whose evidence is
//! [`Evidence::Test`] is driven by a named test in `crates/kr-describe/tests/`, against the
//! deterministic runtime, on the targets the suite has been run on. Every case whose evidence is
//! [`Evidence::NotRun`] is one nothing has run yet, with the owner that will: the cases that need
//! real weights are measured by `scripts/bench-descriptions.sh`, and until a run of it is recorded
//! against a commit and a target they are gaps rather than results.

/// The cases section 22 names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Case {
    /// Titles that are useful rather than generic.
    UsefulTitles,
    /// Claims the evidence does not support: a passed test, an approval, a completion.
    UnsupportedClaims,
    /// Stability over a long run.
    Stability,
    /// The grammar holding.
    Grammar,
    /// Names that are not in English.
    MultilingualNames,
    /// Project text written to mislead.
    MaliciousProjectText,
    /// A turn that runs for a long time.
    LongActiveTurns,
    /// A working directory that changes repeatedly.
    RapidCwdChanges,
    /// The first description after a load.
    ColdStart,
    /// The process-memory ceiling and the reserve.
    Memory,
    /// Descriptions while the processors are busy with the person's own work.
    CpuContention,
    /// Cancelling a job that is running.
    Cancellation,
    /// The queue's fairness bound.
    QueueFairness,
    /// Refusing a result the world has moved past.
    StaleResultRejection,
}

impl Case {
    /// Every case, in the order section 22 lists them.
    pub const ALL: &'static [Self] = &[
        Self::UsefulTitles,
        Self::UnsupportedClaims,
        Self::Stability,
        Self::Grammar,
        Self::MultilingualNames,
        Self::MaliciousProjectText,
        Self::LongActiveTurns,
        Self::RapidCwdChanges,
        Self::ColdStart,
        Self::Memory,
        Self::CpuContention,
        Self::Cancellation,
        Self::QueueFairness,
        Self::StaleResultRejection,
    ];

    /// Returns the stable name this case is reported under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UsefulTitles => "useful_titles",
            Self::UnsupportedClaims => "unsupported_claims",
            Self::Stability => "stability",
            Self::Grammar => "grammar",
            Self::MultilingualNames => "multilingual_names",
            Self::MaliciousProjectText => "malicious_project_text",
            Self::LongActiveTurns => "long_active_turns",
            Self::RapidCwdChanges => "rapid_cwd_changes",
            Self::ColdStart => "cold_start",
            Self::Memory => "memory",
            Self::CpuContention => "cpu_contention",
            Self::Cancellation => "cancellation",
            Self::QueueFairness => "queue_fairness",
            Self::StaleResultRejection => "stale_result_rejection",
        }
    }
}

/// The host architectures a release has to cover.
pub const REQUIRED_TARGETS: &[&str] = &[
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-pc-windows-msvc",
];

/// What stands behind one case.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Evidence {
    /// A test in this repository, against the deterministic runtime.
    Test {
        /// The test's name.
        name: &'static str,
    },
    /// A benchmark run against real weights.
    Benchmark {
        /// The script that runs it.
        script: &'static str,
    },
    /// Something somebody else reported, which this product has not reproduced.
    ReportedNotReproduced {
        /// When it was reported.
        reported_on: &'static str,
        /// What is missing before it could be reproduced.
        missing: &'static str,
    },
    /// Nothing yet.
    NotRun {
        /// Who owns running it.
        owner: &'static str,
    },
}

impl Evidence {
    /// Returns whether this evidence was produced by this product.
    ///
    /// A report somebody supplied is not. Neither is a case nobody has run. Both are in the matrix
    /// so a reader can see the shape of what is known, and neither counts as qualification.
    #[must_use]
    pub const fn qualifies(self) -> bool {
        matches!(self, Self::Test { .. } | Self::Benchmark { .. })
    }
}

/// One case's state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Row {
    /// The case.
    pub case: Case,
    /// What stands behind it in this build.
    pub evidence: Evidence,
    /// Which of the required targets it has actually been exercised on.
    pub targets: &'static [&'static str],
}

/// The 13 September smoke results, carried exactly as they were reported.
///
/// Nothing here is a figure, and that is deliberate. What was supplied was a report; the scripts
/// and the raw outputs were not, so there is nothing this product could reproduce or check. The
/// record therefore says that the report exists, that it has not been reproduced, and that it
/// qualifies nothing - which is what section 22 asks for and the most that can honestly be said.
pub const SMOKE_13_SEPTEMBER: SmokeReport = SmokeReport {
    reported_on: "2026-09-13",
    reproduced: false,
    scripts_supplied: false,
    raw_outputs_supplied: false,
    qualifies_targets: &[],
    note: "Preserved as reported. It qualifies neither the fallback profile nor any reference-host \
           target, because the benchmark scripts and raw outputs behind it were not supplied and \
           nothing here has reproduced it.",
};

/// A set of results somebody else reported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SmokeReport {
    /// When it was reported.
    pub reported_on: &'static str,
    /// Whether this product reproduced it. It did not.
    pub reproduced: bool,
    /// Whether the scripts behind it were supplied. They were not.
    pub scripts_supplied: bool,
    /// Whether the raw outputs were supplied. They were not.
    pub raw_outputs_supplied: bool,
    /// Which targets it qualifies. None.
    pub qualifies_targets: &'static [&'static str],
    /// What a reader needs to know about it.
    pub note: &'static str,
}

/// The qualification matrix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Matrix {
    rows: &'static [Row],
}

/// The targets a test against the deterministic runtime covers.
///
/// A test in this repository runs wherever the test suite runs, so what a passing suite proves on a
/// target is exactly what a run of it on that target proves. These are the targets the suite has
/// been run on and recorded: macOS on Apple silicon and Linux on x86-64, which are the two the
/// build machinery covers. The other three are gaps, and [`Matrix::gaps`] reports them.
const EVERY_TARGET: &[&str] = &["aarch64-apple-darwin", "x86_64-unknown-linux-gnu"];

/// The targets the benchmark has been run on and recorded in this repository.
///
/// It is empty, and that is the point: a run that has not happened is not evidence. A case whose
/// evidence is a benchmark therefore reports every required target as a gap until somebody records
/// a run against a named commit and target.
const BENCHED_TARGETS: &[&str] = &[];

/// The matrix as this build stands.
static BUILTIN: &[Row] = &[
    Row {
        case: Case::UsefulTitles,
        evidence: Evidence::NotRun {
            owner: "scripts/bench-descriptions.sh",
        },
        targets: BENCHED_TARGETS,
    },
    Row {
        case: Case::UnsupportedClaims,
        evidence: Evidence::Test {
            name: "generated_text_cannot_reach_a_status_a_permission_or_a_review",
        },
        targets: EVERY_TARGET,
    },
    Row {
        case: Case::Stability,
        evidence: Evidence::NotRun {
            owner: "scripts/bench-descriptions.sh",
        },
        targets: BENCHED_TARGETS,
    },
    Row {
        case: Case::Grammar,
        evidence: Evidence::Test {
            name: "a_result_that_is_not_the_grammars_object_is_rejected_rather_than_tidied",
        },
        targets: EVERY_TARGET,
    },
    Row {
        case: Case::MultilingualNames,
        evidence: Evidence::Test {
            name: "a_title_is_bounded_in_codepoints_rather_than_bytes",
        },
        targets: EVERY_TARGET,
    },
    Row {
        case: Case::MaliciousProjectText,
        evidence: Evidence::Test {
            name: "project_text_that_gives_instructions_is_carried_as_data_and_changes_nothing",
        },
        targets: EVERY_TARGET,
    },
    Row {
        case: Case::LongActiveTurns,
        evidence: Evidence::Test {
            name: "a_session_changing_continuously_still_settles_every_debounce",
        },
        targets: EVERY_TARGET,
    },
    Row {
        case: Case::RapidCwdChanges,
        evidence: Evidence::Test {
            name: "rapid_directory_changes_coalesce_into_one_revision",
        },
        targets: EVERY_TARGET,
    },
    Row {
        case: Case::ColdStart,
        evidence: Evidence::NotRun {
            owner: "scripts/bench-descriptions.sh",
        },
        targets: BENCHED_TARGETS,
    },
    Row {
        case: Case::Memory,
        evidence: Evidence::Test {
            name: "a_reserve_that_cannot_be_held_pauses_rather_than_loads",
        },
        targets: EVERY_TARGET,
    },
    Row {
        case: Case::CpuContention,
        evidence: Evidence::NotRun {
            owner: "scripts/bench-descriptions.sh",
        },
        targets: BENCHED_TARGETS,
    },
    Row {
        case: Case::Cancellation,
        evidence: Evidence::Test {
            name: "a_cancelled_job_publishes_nothing_and_keeps_the_title_it_had",
        },
        targets: EVERY_TARGET,
    },
    Row {
        case: Case::QueueFairness,
        evidence: Evidence::Test {
            name: "an_oldest_ordinary_job_runs_after_three_priority_jobs",
        },
        targets: EVERY_TARGET,
    },
    Row {
        case: Case::StaleResultRejection,
        evidence: Evidence::Test {
            name: "a_result_from_a_remapped_profile_is_refused_as_stale",
        },
        targets: EVERY_TARGET,
    },
];

impl Matrix {
    /// Returns the matrix as this build stands.
    #[must_use]
    pub const fn builtin() -> Self {
        Self { rows: BUILTIN }
    }

    /// Returns every row.
    #[must_use]
    pub const fn rows(&self) -> &'static [Row] {
        self.rows
    }

    /// Returns the row for one case.
    #[must_use]
    pub fn row(&self, case: Case) -> Option<&'static Row> {
        self.rows.iter().find(|row| row.case == case)
    }

    /// Returns the cases with no row at all, which is a fault in this matrix rather than in a host.
    #[must_use]
    pub fn uncovered(&self) -> Vec<Case> {
        Case::ALL
            .iter()
            .copied()
            .filter(|case| self.row(*case).is_none())
            .collect()
    }

    /// Returns the case and target pairs that have not been exercised.
    ///
    /// This is the honest half of the matrix and it is a method rather than a comment, so a report
    /// that prints the matrix prints the gaps with it.
    #[must_use]
    pub fn gaps(&self) -> Vec<(Case, &'static str)> {
        let mut gaps = Vec::new();
        for row in self.rows {
            for target in REQUIRED_TARGETS {
                if !row.targets.contains(target) {
                    gaps.push((row.case, *target));
                }
            }
        }
        gaps
    }
}
