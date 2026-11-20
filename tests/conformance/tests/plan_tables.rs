//! Core's plan file and the code tables it replaces: the file is generated from the tables, and one
//! case holds the two equal for every platform and every selection of groups.

use std::path::{Path, PathBuf};

use kr_conformance::plan::{self, ApplicationsPlan, Group, Platform, Reading, Step};
use kr_conformance::plan_file::{
    Applications, CaseTable, ExcludedPackage, GroupAbsent, IgnoredRun, Lane, PerPlatform, Plan,
    ReadingKind, Reasoned, Runs, SkipsFrom, StepDef, Terminals, TypeScript, Unrun,
};

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

const PLATFORMS: [Platform; 3] = [Platform::Linux, Platform::MacOs, Platform::Windows];

/// The words the loader adds to `step`'s command, taken out again.
fn without_expansion(step: &Step, applications: bool) -> Vec<String> {
    let mut words = step.command.clone();
    if !applications {
        for _ in &step.skips {
            let value = words.pop();
            let flag = words.pop();
            let name = value.as_deref();
            assert_eq!(flag.as_deref(), Some("--skip"), "{name:?}");
        }
    }
    let cargo_test = words.first().map(String::as_str) == Some("cargo")
        && words.get(1).map(String::as_str) == Some("test")
        && step.reading == Reading::Cargo;
    if cargo_test && !words.iter().any(|word| word == "--nocapture") {
        assert_eq!(
            words.pop().as_deref(),
            Some("--show-output"),
            "{}",
            step.line()
        );
        if words.last().map(String::as_str) == Some("--") {
            words.pop();
        }
    }
    words
}

fn definition(step: &Step, platforms: Vec<Platform>) -> StepDef {
    let applications = step
        .needs
        .iter()
        .any(|need| need == plan::APPLICATIONS_VARIABLE);
    let (reading, package, lane) = match &step.reading {
        Reading::Cargo => (ReadingKind::Cargo, None, None),
        Reading::Build => (ReadingKind::Build, None, None),
        Reading::Vitest { directory } => (ReadingKind::Vitest, Some(directory.clone()), None),
        Reading::Lane(tests) => (ReadingKind::Lane, None, Some(*tests)),
    };
    StepDef {
        id: String::new(),
        group: step.group.clone(),
        what: step.what.clone(),
        platforms,
        command: without_expansion(step, applications),
        reading,
        package,
        lane,
        needs: step.needs.clone(),
        filter: step.filter.as_ref().map(|(name, reason)| Reasoned {
            name: name.clone(),
            reason: reason.clone(),
        }),
        skips: if applications {
            Vec::new()
        } else {
            step.skips
                .iter()
                .map(|(name, reason)| Reasoned {
                    name: name.clone(),
                    reason: reason.clone(),
                })
                .collect()
        },
        skips_from: applications.then_some(SkipsFrom::Applications),
    }
}

type Entry = (Step, Vec<Platform>);

/// The union of two lists, each platform's own order kept, equal steps taken once.
fn merge(left: Vec<Entry>, right: Vec<Entry>) -> Vec<Entry> {
    let (n, m) = (left.len(), right.len());
    let mut lcs = vec![vec![0_usize; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            lcs[i][j] = if left[i].0 == right[j].0 {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }
    let (mut i, mut j) = (0, 0);
    let mut out = Vec::new();
    while i < n || j < m {
        if i < n && j < m && left[i].0 == right[j].0 {
            let mut entry = left[i].clone();
            entry.1.extend(right[j].1.clone());
            out.push(entry);
            i += 1;
            j += 1;
        } else if i < n && (j == m || lcs[i + 1][j] >= lcs[i][j + 1]) {
            out.push(left[i].clone());
            i += 1;
        } else {
            out.push(right[j].clone());
            j += 1;
        }
    }
    out
}

fn slug(text: &str) -> String {
    let mut out = String::new();
    for c in text.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        } else if !out.ends_with('-') && !out.is_empty() {
            out.push('-');
        }
    }
    let mut cut = out.trim_end_matches('-').to_owned();
    if cut.len() > 56 {
        cut.truncate(56);
        if let Some(at) = cut.rfind('-') {
            cut.truncate(at);
        }
    }
    cut
}

fn run_of(runs: &plan::Runs) -> Runs {
    let own = |text: &str| text.to_owned();
    match *runs {
        plan::Runs::Command { file, line } => Runs::Command {
            file: own(file),
            line: own(line),
        },
        plan::Runs::Supplied {
            file,
            line,
            names_with,
        } => Runs::Supplied {
            file: own(file),
            line: own(line),
            names_with: names_with.iter().map(|word| own(word)).collect(),
        },
        plan::Runs::Plan { line } => Runs::Plan { line: own(line) },
        plan::Runs::Helper { file } => Runs::Helper { file: own(file) },
        plan::Runs::ByHand { why } => Runs::ByHand { why: own(why) },
        plan::Runs::Nowhere { why } => Runs::Nowhere { why: own(why) },
    }
}

/// The plan the code tables give.
fn tables() -> Plan {
    let applications = ApplicationsPlan {
        left_out: Vec::new(),
    };
    let on = |platform: Platform| -> Vec<Entry> {
        plan::steps(platform, &Group::ALL, "{evidence}", Some(&applications))
            .into_iter()
            .map(|step| (step, vec![platform]))
            .collect()
    };
    let mut merged = merge(on(Platform::Linux), on(Platform::MacOs));
    let windows = on(Platform::Windows);
    let at = merged
        .iter()
        .rposition(|(step, _)| step.group == "rust")
        .map_or(0, |index| index + 1);
    merged.splice(at..at, windows);
    let mut steps: Vec<StepDef> = Vec::new();
    for (step, platforms) in merged {
        let mut def = definition(&step, platforms);
        let base = format!("{}-{}", def.group, slug(&def.what));
        let mut id = base.clone();
        let mut n = 1;
        while steps.iter().any(|other| other.id == id) {
            n += 1;
            id = format!("{base}-{n}");
        }
        def.id = id;
        steps.push(def);
    }
    let mut group_absent = Vec::new();
    for group in Group::ALL {
        for platform in PLATFORMS {
            if let Some(reason) = plan::group_absent_reason(group, platform) {
                group_absent.push(GroupAbsent {
                    group: group.name().to_owned(),
                    platform,
                    reason: reason.to_owned(),
                    explains_unrun_rust: matches!(group, Group::EndToEnd | Group::Performance),
                });
            }
        }
    }
    Plan {
        repository: "kalareach".to_owned(),
        groups: Group::ALL
            .iter()
            .map(|group| group.name().to_owned())
            .collect(),
        list_table_rows: true,
        steps,
        excluded_packages: plan::MACOS_EXCLUDED
            .iter()
            .map(|(package, reason)| ExcludedPackage {
                platform: Platform::MacOs,
                package: (*package).to_owned(),
                reason: (*reason).to_owned(),
            })
            .collect(),
        group_absent,
        unrun: Unrun {
            rust: PerPlatform {
                linux: plan::unrun_reason(Platform::Linux).to_owned(),
                macos: plan::unrun_reason(Platform::MacOs).to_owned(),
                windows: plan::unrun_reason(Platform::Windows).to_owned(),
            },
            bench: "a benchmark target: the performance group runs the measurements it holds"
                .to_owned(),
            typescript: "no step of this run's selection runs the TypeScript suites".to_owned(),
        },
        case_tables: plan::CASE_TABLES
            .iter()
            .map(|table| CaseTable {
                files: table.files.to_owned(),
                package: table.package.to_owned(),
                target: table.target.to_owned(),
                tests: table.tests.iter().map(|test| (*test).to_owned()).collect(),
            })
            .collect(),
        ignored_runs: plan::IGNORED_RUNS
            .iter()
            .map(|run| IgnoredRun {
                package: run.package.to_owned(),
                target: run.target.to_owned(),
                cases: run.cases.iter().map(|case| (*case).to_owned()).collect(),
                runs: run_of(&run.runs),
            })
            .collect(),
        lanes: plan::LANES
            .iter()
            .map(|lane| Lane {
                group: lane
                    .files
                    .starts_with("apps/companion/native/")
                    .then(|| "phones".to_owned()),
                files: lane.files.to_owned(),
                reason: lane.reason.to_owned(),
                reads: lane.reads,
            })
            .collect(),
        terminals: Some(Terminals {
            names: plan::TERMINALS
                .iter()
                .map(|name| (*name).to_owned())
                .collect(),
            reason: plan::TERMINAL_REASON.to_owned(),
        }),
        typescript: Some(TypeScript {
            packages: plan::TYPESCRIPT_PACKAGES
                .iter()
                .map(|package| (*package).to_owned())
                .collect(),
        }),
        applications: Some(Applications {
            lock: "tests/conformance/applications.lock".to_owned(),
        }),
    }
}

/// A TOML string: a literal one where it needs no escape, a basic one otherwise.
fn text(value: &str) -> String {
    let plain = !value.chars().any(|c| c.is_control() && c != '\t');
    if plain && !value.contains('\'') {
        return format!("'{value}'");
    }
    if plain && !value.contains("'''") && !value.ends_with('\'') {
        return format!("'''{value}'''");
    }
    let mut out = String::from("\"");
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn list(key: &str, values: &[String]) -> String {
    let items: Vec<String> = values.iter().map(|value| text(value)).collect();
    let one = format!("{key} = [{}]", items.join(", "));
    if one.len() <= 100 {
        return one;
    }
    let mut out = format!("{key} = [\n");
    for item in items {
        out.push_str(&format!("    {item},\n"));
    }
    out.push(']');
    out
}

fn platform_name(platform: Platform) -> String {
    platform.name().to_owned()
}

/// The plan as the TOML text the file holds.
fn render(plan: &Plan) -> String {
    let mut out = String::new();
    let mut line = |text: String| {
        out.push_str(&text);
        out.push('\n');
    };
    line(
        "# What the conformance report runs and reads in this repository. `kr-conformance` reads"
            .to_owned(),
    );
    line("# this file for `map` and for `run`; a step runs the argument vector it names, never a shell".to_owned());
    line(
        "# string. The loader adds `--show-output` after `--` to each `cargo test` that leaves its"
            .to_owned(),
    );
    line("# output captured, and `--skip <name>` for each entry of a step's `skips`.".to_owned());
    line(format!("repository = {}", text(&plan.repository)));
    line(list("groups", &plan.groups));
    line(format!("list_table_rows = {}", plan.list_table_rows));
    if let Some(typescript) = &plan.typescript {
        line(String::new());
        line("[typescript]".to_owned());
        line(list("packages", &typescript.packages));
    }
    if let Some(applications) = &plan.applications {
        line(String::new());
        line("[applications]".to_owned());
        line(format!("lock = {}", text(&applications.lock)));
    }
    line(String::new());
    line("# Why a test that no step runs is not run.".to_owned());
    line("[unrun]".to_owned());
    line(format!("bench = {}", text(&plan.unrun.bench)));
    line(format!("typescript = {}", text(&plan.unrun.typescript)));
    line(String::new());
    line("[unrun.rust]".to_owned());
    for platform in PLATFORMS {
        line(format!(
            "{} = {}",
            platform.name(),
            text(plan.unrun.rust.get(platform))
        ));
    }
    if let Some(terminals) = &plan.terminals {
        line(String::new());
        line("[terminals]".to_owned());
        line(list("names", &terminals.names));
        line(format!("reason = {}", text(&terminals.reason)));
    }
    for absent in &plan.group_absent {
        line(String::new());
        line("[[group_absent]]".to_owned());
        line(format!("group = {}", text(&absent.group)));
        line(format!(
            "platform = {}",
            text(&platform_name(absent.platform))
        ));
        line(format!("reason = {}", text(&absent.reason)));
        if absent.explains_unrun_rust {
            line("explains_unrun_rust = true".to_owned());
        }
    }
    for excluded in &plan.excluded_packages {
        line(String::new());
        line("[[excluded_package]]".to_owned());
        line(format!(
            "platform = {}",
            text(&platform_name(excluded.platform))
        ));
        line(format!("package = {}", text(&excluded.package)));
        line(format!("reason = {}", text(&excluded.reason)));
    }
    for lane in &plan.lanes {
        line(String::new());
        line("[[lane]]".to_owned());
        if let Some(group) = &lane.group {
            line(format!("group = {}", text(group)));
        }
        line(format!("files = {}", text(&lane.files)));
        line(format!("reason = {}", text(&lane.reason)));
        if let Some(reads) = lane.reads {
            line(format!(
                "reads = {}",
                text(&format!("{reads:?}").to_lowercase())
            ));
        }
    }
    for table in &plan.case_tables {
        line(String::new());
        line("[[case_table]]".to_owned());
        line(format!("files = {}", text(&table.files)));
        line(format!("package = {}", text(&table.package)));
        line(format!("target = {}", text(&table.target)));
        line(list("tests", &table.tests));
    }
    for step in &plan.steps {
        line(String::new());
        line("[[step]]".to_owned());
        line(format!("id = {}", text(&step.id)));
        line(format!("group = {}", text(&step.group)));
        line(format!("what = {}", text(&step.what)));
        let platforms: Vec<String> = step.platforms.iter().map(|p| platform_name(*p)).collect();
        line(list("platforms", &platforms));
        let reading = format!("{:?}", step.reading).to_lowercase();
        line(format!("reading = {}", text(&reading)));
        if let Some(package) = &step.package {
            line(format!("package = {}", text(package)));
        }
        if let Some(lane) = step.lane {
            line(format!(
                "lane = {}",
                text(&format!("{lane:?}").to_lowercase())
            ));
        }
        if !step.needs.is_empty() {
            line(list("needs", &step.needs));
        }
        if step.skips_from.is_some() {
            line("skips_from = 'applications'".to_owned());
        }
        line(list("command", &step.command));
        if let Some(filter) = &step.filter {
            line("[step.filter]".to_owned());
            line(format!("name = {}", text(&filter.name)));
            line(format!("reason = {}", text(&filter.reason)));
        }
        for skip in &step.skips {
            line("[[step.skips]]".to_owned());
            line(format!("name = {}", text(&skip.name)));
            line(format!("reason = {}", text(&skip.reason)));
        }
    }
    for run in &plan.ignored_runs {
        line(String::new());
        line("[[ignored_run]]".to_owned());
        line(format!("package = {}", text(&run.package)));
        line(format!("target = {}", text(&run.target)));
        if !run.cases.is_empty() {
            line(list("cases", &run.cases));
        }
        line("[ignored_run.runs]".to_owned());
        match &run.runs {
            Runs::Command { file, line: words } => {
                line("kind = 'command'".to_owned());
                line(format!("file = {}", text(file)));
                line(format!("line = {}", text(words)));
            }
            Runs::Supplied {
                file,
                line: words,
                names_with,
            } => {
                line("kind = 'supplied'".to_owned());
                line(format!("file = {}", text(file)));
                line(format!("line = {}", text(words)));
                line(list("names_with", names_with));
            }
            Runs::Plan { line: words } => {
                line("kind = 'plan'".to_owned());
                line(format!("line = {}", text(words)));
            }
            Runs::Helper { file } => {
                line("kind = 'helper'".to_owned());
                line(format!("file = {}", text(file)));
            }
            Runs::ByHand { why } => {
                line("kind = 'by_hand'".to_owned());
                line(format!("why = {}", text(why)));
            }
            Runs::Nowhere { why } => {
                line("kind = 'nowhere'".to_owned());
                line(format!("why = {}", text(why)));
            }
        }
    }
    out
}

/// Writes core's plan file from the code tables. Run by hand:
/// `cargo test -p kr-conformance --test plan_tables -- --ignored`.
#[test]
#[ignore = "writes conformance/plan.toml from the code tables; run by hand"]
fn write_core_s_plan_file() {
    let path = repository().join(kr_conformance::plan_file::PLAN_PATH);
    std::fs::create_dir_all(path.parent().expect("a directory")).expect("the directory");
    std::fs::write(&path, render(&tables())).expect("the file");
}

fn selections() -> Vec<Vec<Group>> {
    (0_u32..(1 << Group::ALL.len()))
        .map(|bits| {
            Group::ALL
                .iter()
                .enumerate()
                .filter(|(index, _)| bits & (1 << index) != 0)
                .map(|(_, group)| *group)
                .collect()
        })
        .collect()
}

fn names(groups: &[Group]) -> Vec<String> {
    groups.iter().map(|group| group.name().to_owned()).collect()
}

/// The first difference between a plan and the code tables, named, or `None`.
fn difference(file: &Plan) -> Option<String> {
    let code = tables();
    if file.repository != code.repository || file.groups != code.groups {
        return Some("the repository or the groups differ".to_owned());
    }
    let applications = [
        None,
        Some(ApplicationsPlan {
            left_out: vec![("htop".to_owned(), "no build here".to_owned())],
        }),
    ];
    for platform in PLATFORMS {
        for groups in selections() {
            for left_out in &applications {
                let wanted = plan::steps(platform, &groups, "/tmp/e", left_out.as_ref());
                let given = file.steps(platform, &names(&groups), "/tmp/e", left_out.as_ref());
                if wanted.len() != given.len() {
                    return Some(format!(
                        "on {platform:?} for {:?}: {} steps against the tables' {}",
                        names(&groups),
                        given.len(),
                        wanted.len()
                    ));
                }
                for (index, (wanted, given)) in wanted.iter().zip(&given).enumerate() {
                    if wanted != given {
                        return Some(format!(
                            "on {platform:?} for {:?}, step {} `{}`: the file's `{}` against the tables' `{}`; \
                             the file's skips {:?}, filter {:?}, needs {:?}",
                            names(&groups),
                            index + 1,
                            wanted.what,
                            given.line(),
                            wanted.line(),
                            given.skips,
                            given.filter,
                            given.needs
                        ));
                    }
                }
            }
        }
    }
    for (what, same) in [
        (
            "the excluded packages",
            file.excluded_packages == code.excluded_packages,
        ),
        ("the absent groups", file.group_absent == code.group_absent),
        ("the unrun reasons", file.unrun == code.unrun),
        ("the case tables", file.case_tables == code.case_tables),
        ("the ignored runs", file.ignored_runs == code.ignored_runs),
        ("the lanes", file.lanes == code.lanes),
        ("the terminals", file.terminals == code.terminals),
        (
            "the TypeScript packages",
            file.typescript == code.typescript,
        ),
        (
            "the applications lock",
            file.applications == code.applications,
        ),
        (
            "the listed rows",
            file.list_table_rows == code.list_table_rows,
        ),
    ] {
        if !same {
            return Some(format!("{what} differ"));
        }
    }
    (file != &code)
        .then(|| "the step definitions differ in a field that no selection reads".to_owned())
}

fn core_s_file() -> (String, Plan) {
    let text = std::fs::read_to_string(repository().join(kr_conformance::plan_file::PLAN_PATH))
        .expect("core's plan file");
    let plan = Plan::parse(&text, &repository()).expect("core's plan file loads");
    (text, plan)
}

/// The file the generator writes is the file in the tree, and it loads to what the code tables give,
/// for every platform and every selection of groups, with and without an applications plan.
#[test]
fn core_s_file_loads_to_what_the_code_tables_give() {
    let (text, loaded) = core_s_file();
    assert_eq!(difference(&loaded), None);
    assert_eq!(
        text,
        render(&tables()),
        "the file is what the generator writes"
    );
}

#[test]
fn a_planted_edit_of_the_file_is_reported_and_named() {
    let (text, _) = core_s_file();
    let load = |edited: &str| Plan::parse(edited, &repository()).expect("the edited file loads");
    // A skip's reason.
    let reason = "needs podman, which the macOS runner does not have; the Linux run hosts it";
    let edited = text.replacen(reason, "needs podman", 1);
    assert_ne!(edited, text);
    let found = difference(&load(&edited)).expect("a difference");
    assert!(
        found.contains("MacOs") && found.contains("skips"),
        "{found}"
    );
    // A command word.
    let edited = text.replacen("'--no-fail-fast',", "'--no-fail-fast', '--quiet',", 1);
    assert_ne!(edited, text);
    let found = difference(&load(&edited)).expect("a difference");
    assert!(found.contains("--quiet"), "{found}");
    // Two steps swapped: the first two steps of the file, by their ids.
    let mut plan = load(&text);
    plan.steps.swap(0, 1);
    let found = difference(&plan).expect("a difference");
    assert!(found.contains("step 1"), "{found}");
}

fn flags_by_the_tables(platform: Platform, groups: &[Group]) -> [String; 7] {
    let typescript = groups.contains(&Group::TypeScript);
    let applications = groups.contains(&Group::Applications);
    let unrun = groups
        .iter()
        .filter(|group| matches!(group, Group::EndToEnd | Group::Performance))
        .find_map(|group| plan::group_absent_reason(*group, platform))
        .filter(|_| platform == Platform::Windows);
    [
        typescript.to_string(),
        groups.contains(&Group::Phones).to_string(),
        applications.to_string(),
        (applications && platform != Platform::Windows).to_string(),
        (typescript && platform != Platform::Windows).to_string(),
        format!("{unrun:?}"),
        if typescript {
            plan::group_absent_reason(Group::TypeScript, platform)
                .unwrap_or("no step of this run's selection runs the TypeScript suites")
                .to_owned()
        } else {
            String::new()
        },
    ]
}

fn flags_by_the_file(plan: &Plan, platform: Platform, groups: &[Group]) -> [String; 7] {
    let selected = names(groups);
    let typescript = plan.reads_typescript(&selected);
    let package_places = plan
        .typescript_packages()
        .iter()
        .all(|package| plan.selects_package(&selected, package) == typescript);
    assert!(package_places, "{selected:?}");
    [
        typescript.to_string(),
        plan.selects_lane_file(&selected, "apps/companion/native/ios/Tests/A.swift")
            .to_string(),
        plan.selects_applications(&selected).to_string(),
        plan.runs_applications(platform, &selected).to_string(),
        plan.uses_javascript_tools(platform, &selected).to_string(),
        format!("{:?}", plan.unrun_rust_reason(platform, &selected)),
        if typescript {
            plan.typescript_unrun_reason(platform, &selected).to_owned()
        } else {
            String::new()
        },
    ]
}

/// Every decision the code takes from a group's name today (does the run read TypeScript, select
/// the lanes' places, need the applications, record Node and pnpm, give the Windows reason for an
/// unrun Rust target, say why a TypeScript test is not run) is what the file's steps give.
#[test]
fn every_decision_the_code_takes_from_a_group_name_is_the_files() {
    let (_, loaded) = core_s_file();
    for platform in PLATFORMS {
        for groups in selections() {
            assert_eq!(
                flags_by_the_file(&loaded, platform, &groups),
                flags_by_the_tables(platform, &groups),
                "{platform:?} {:?}",
                names(&groups)
            );
        }
    }
    // A plan whose groups carry other names reads TypeScript wherever it has a vitest step.
    let planted = r"
repository = 'planted'
groups = ['unit', 'browsers', 'node']
[unrun]
bench = 'b'
typescript = 't'
[unrun.rust]
linux = 'l'
macos = 'm'
windows = 'w'
[[step]]
id = 'unit-tests'
group = 'unit'
what = 'the unit tests'
platforms = ['linux']
reading = 'vitest'
package = '.'
command = ['pnpm', 'run', 'test']
[[step]]
id = 'build'
group = 'node'
what = 'a build'
platforms = ['linux']
reading = 'build'
command = ['cargo', 'build']
";
    let plan = Plan::parse(planted, &repository()).expect("the planted plan loads");
    let unit = vec!["unit".to_owned()];
    let others = vec!["browsers".to_owned(), "node".to_owned()];
    assert!(plan.reads_typescript(&unit));
    assert!(!plan.reads_typescript(&others));
    assert!(plan.uses_javascript_tools(Platform::Linux, &unit));
    assert!(!plan.uses_javascript_tools(Platform::Windows, &unit));
    assert!(!plan.uses_javascript_tools(Platform::Linux, &others));
}

/// Each way a command is expanded gives the words the code gives: a captured test output, an
/// uncaptured one, the skips of a step, the one raw skip of the Windows startup step, and a build.
#[test]
fn the_one_expansion_rule_gives_the_words_the_code_gives() {
    let (_, loaded) = core_s_file();
    let code =
        |platform: Platform, group: &str| plan::steps(platform, &names_of(group), "/tmp/e", None);
    fn names_of(group: &str) -> Vec<Group> {
        vec![Group::named(group).expect("a group")]
    }
    // Captured: the Linux workspace step. Structured skips: the macOS one. Uncaptured: a
    // measurement. Raw skip: the Windows startup step. Build: the end-to-end build.
    let cases = [
        (
            Platform::Linux,
            "rust",
            "cargo test --locked --workspace --no-fail-fast -- --show-output",
        ),
        (
            Platform::Windows,
            "rust",
            "--test startup_windows -- --ignored --skip a_task_the_task_scheduler_does_not_start --show-output",
        ),
        (
            Platform::Linux,
            "performance",
            "-- --ignored --exact --nocapture attach_to_a_usable_screen",
        ),
        (
            Platform::MacOs,
            "rust",
            "--no-fail-fast -- --show-output --skip the_helper_inside_a_container",
        ),
        (
            Platform::Linux,
            "end-to-end",
            "cargo build --locked -p kr-worker --bin kr-worker",
        ),
    ];
    for (platform, group, line) in cases {
        let wanted: Vec<String> = code(platform, group).iter().map(Step::line).collect();
        assert!(
            wanted.iter().any(|candidate| candidate.contains(line)),
            "{platform:?} {group}: {line}"
        );
        let given: Vec<String> = loaded
            .steps(platform, &[group.to_owned()], "/tmp/e", None)
            .iter()
            .map(Step::line)
            .collect();
        assert_eq!(given, wanted, "{platform:?} {group}");
    }
}
