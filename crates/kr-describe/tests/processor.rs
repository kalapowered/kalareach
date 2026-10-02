//! The processor the description process needs: a host whose processor lacks an instruction set the
//! process's build uses is offered no model, and the set the build uses is the set this crate says.
//!
//! Nothing here starts a process. The point of the selection is that the process is never started
//! on a processor that would stop it with an illegal instruction.

mod support;

use std::collections::BTreeMap;

use kr_describe::context::ContextSignal;
use kr_describe::metadata::RepositoryFacts;
use kr_describe::processor::{Feature, Features, baseline, names};
use kr_describe::profile::catalogue::{MetGates, NotSelected, Selection};
use kr_describe::resource::ResourceSettings;
use kr_describe::service::{DescriptionService, HostPlacement, Instruction};
use kr_describe::store::DescriptionStore;
use kr_protocol::ids::SessionEpoch;

use support::{MAC, at, binding, built_in, native, roomy, session};

const LINUX: &str = "x86_64-unknown-linux-gnu";

/// A processor with every instruction set the build asks for, but `without`.
fn all_but(without: Feature) -> Features {
    Features::of(
        Feature::X86_64
            .into_iter()
            .filter(|feature| *feature != without),
    )
}

/// A processor with every instruction set the build asks for.
fn full() -> Features {
    Features::of(Feature::X86_64)
}

/// A processor that lacks one instruction set the description process's build uses is offered no
/// model for any of the profiles, whichever set it is, and the reason names the set. The control is
/// the same target on a processor that has them all, which selects the default.
#[test]
fn a_processor_without_an_instruction_set_the_build_uses_is_offered_no_model() {
    let catalogue = built_in();
    for missing in Feature::X86_64 {
        let selection = catalogue.select(LINUX, &all_but(missing), &MetGates::all());
        let Selection::DeterministicMetadata { reasons } = &selection else {
            panic!(
                "a processor without {} was offered a model",
                missing.as_str()
            );
        };
        assert_eq!(reasons.len(), 2, "both profiles are refused");
        assert!(
            reasons
                .iter()
                .all(|(_, why)| *why == NotSelected::ProcessorLacks(vec![missing])),
            "{reasons:?}"
        );
        assert_eq!(selection.processor_lacks(), Some(&[missing][..]));
    }

    let selection = catalogue.select(LINUX, &full(), &MetGates::all());
    assert_eq!(
        selection.profile().map(|profile| profile.profile_id()),
        Some("minicpm5-2b-q4-k-m"),
        "the control: a processor with every set selects the default"
    );
    assert_eq!(selection.processor_lacks(), None);
}

/// A service on a host whose processor lacks an instruction set offers nothing at setup, says which
/// set in the reason, and never asks for the description process to be started, however much work
/// is queued. The control is the same host on a processor that has them all, which offers the model
/// and asks for a load.
#[test]
fn a_host_whose_processor_lacks_an_instruction_set_says_which_and_starts_no_process() {
    let host = |processor: Features| {
        let mut service = DescriptionService::new(
            HostPlacement {
                environment: native(1),
                data_access: None,
                target: LINUX.to_owned(),
                processor,
            },
            built_in(),
            MetGates::default(),
            ResourceSettings::default(),
            DescriptionStore::in_memory().expect("a store in memory"),
        );
        let now = at(10_000);
        service.session_opened(session(1), SessionEpoch::V1, binding());
        service.observe(
            &session(1),
            ContextSignal::WorkingDirectory {
                directory: "kalareach".to_owned(),
                repository: Some(RepositoryFacts {
                    name: "kalareach".to_owned(),
                    branch: Some("main".to_owned()),
                }),
            },
            now,
        );
        service.settle(
            &session(1),
            kr_describe::queue::Priority::Ordinary,
            now.after_ms(2_000),
        );
        service
    };

    let mut lacking = host(all_but(Feature::Avx2));
    let setup = lacking.setup_state();
    assert!(!setup.offered);
    assert_eq!(setup.profile_id, None);
    assert_eq!(setup.processor_lacks, [Feature::Avx2]);
    assert_eq!(
        setup.unavailable.as_deref(),
        Some("this processor lacks AVX2, which the description process needs")
    );
    let asked = lacking.next(&roomy(), at(20_000)).expect("an instruction");
    assert!(
        matches!(asked, Instruction::Wait { until_ms: None }),
        "{asked:?}"
    );

    let mut full_host = host(full());
    let setup = full_host.setup_state();
    assert!(setup.offered);
    assert!(setup.processor_lacks.is_empty());
    assert_eq!(setup.unavailable, None);
    let asked = full_host
        .next(&roomy(), at(20_000))
        .expect("an instruction");
    assert!(matches!(asked, Instruction::Load { .. }), "{asked:?}");
}

/// The instruction sets the compiler adds on its own (POPCNT with SSE4.2, the scalar BMI, LZCNT and
/// MOVBE with the AVX2 level) have no llama.cpp option, and a hypervisor can hide any of them from a
/// processor that has the six that do. Each is checked like the rest, and the reason names it.
#[test]
fn an_instruction_set_the_compiler_implies_is_checked_like_the_pinned_ones() {
    let implied = [
        Feature::Popcnt,
        Feature::Bmi1,
        Feature::Lzcnt,
        Feature::Movbe,
    ];
    for missing in implied {
        assert_eq!(missing.build_option(), None, "{}", missing.as_str());
        let selection = built_in().select(LINUX, &all_but(missing), &MetGates::default());
        assert_eq!(
            selection.processor_lacks(),
            Some(&[missing][..]),
            "{}",
            missing.as_str()
        );
    }
    let pinned: Vec<_> = Feature::X86_64
        .iter()
        .filter(|feature| feature.build_option().is_some())
        .collect();
    assert_eq!(pinned.len(), 6, "{pinned:?}");
    assert_eq!(Feature::X86_64.len(), 10);
}

/// A processor that lacks several is told all of them, in the baseline's order, so one answer says
/// everything that is missing.
#[test]
fn every_missing_instruction_set_is_named_in_one_answer() {
    let processor = Features::of([Feature::Sse42, Feature::Avx]);
    let selection = built_in().select(LINUX, &processor, &MetGates::default());
    assert_eq!(
        selection.processor_lacks(),
        Some(
            &[
                Feature::Popcnt,
                Feature::Avx2,
                Feature::Bmi1,
                Feature::Bmi2,
                Feature::Fma,
                Feature::F16c,
                Feature::Lzcnt,
                Feature::Movbe,
            ][..]
        )
    );
    assert_eq!(
        names(selection.processor_lacks().expect("it lacks some")),
        "POPCNT, AVX2, BMI1, BMI2, FMA, F16C, LZCNT and MOVBE"
    );
}

/// The check is made for the target the build is for: a target that is not x86-64 asks nothing of
/// the processor, so the same empty processor that is refused on x86-64 selects the default there.
#[test]
fn a_target_that_is_not_x86_64_asks_nothing_of_the_processor() {
    let none = Features::of([]);
    let on_arm = built_in().select(MAC, &none, &MetGates::default());
    assert_eq!(
        on_arm.profile().map(|profile| profile.profile_id()),
        Some("minicpm5-2b-q4-k-m")
    );
    let on_x86 = built_in().select(LINUX, &none, &MetGates::default());
    assert!(on_x86.profile().is_none());

    for target in [
        "aarch64-apple-darwin",
        "aarch64-unknown-linux-gnu",
        "aarch64-pc-windows-msvc",
        "unknown",
    ] {
        assert!(baseline(target).is_empty(), "{target}");
    }
    for target in [
        "x86_64-apple-darwin",
        "x86_64-unknown-linux-gnu",
        "x86_64-pc-windows-msvc",
        "x86_64-pc-windows-gnu",
    ] {
        assert_eq!(baseline(target), Feature::X86_64, "{target}");
    }
}

/// Where a target has no profile, that reason comes first and the processor is not asked: a
/// processor is never blamed for a platform that has no model.
#[test]
fn a_target_no_profile_lists_is_refused_for_the_target_not_the_processor() {
    let none = Features::of([]);
    let Selection::DeterministicMetadata { reasons } =
        built_in().select("x86_64-unknown-freebsd", &none, &MetGates::all())
    else {
        panic!("a target no profile lists selects nothing");
    };
    assert!(
        reasons
            .iter()
            .all(|(_, why)| *why == NotSelected::IncompatibleTarget),
        "{reasons:?}"
    );
}

/// The processor this test runs on is asked, not assumed: what `running` says it has is what the
/// processor reports, instruction set by instruction set.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[test]
fn the_running_processor_is_asked_for_each_instruction_set() {
    let running = Features::running();
    assert_eq!(
        running.has(Feature::Sse42),
        std::arch::is_x86_feature_detected!("sse4.2")
    );
    assert_eq!(
        running.has(Feature::Avx),
        std::arch::is_x86_feature_detected!("avx")
    );
    assert_eq!(
        running.has(Feature::Avx2),
        std::arch::is_x86_feature_detected!("avx2")
    );
    assert_eq!(
        running.has(Feature::Bmi2),
        std::arch::is_x86_feature_detected!("bmi2")
    );
    assert_eq!(
        running.has(Feature::Fma),
        std::arch::is_x86_feature_detected!("fma")
    );
    assert_eq!(
        running.has(Feature::F16c),
        std::arch::is_x86_feature_detected!("f16c")
    );
    assert_eq!(
        running.has(Feature::Popcnt),
        std::arch::is_x86_feature_detected!("popcnt")
    );
    assert_eq!(
        running.has(Feature::Bmi1),
        std::arch::is_x86_feature_detected!("bmi1")
    );
    assert_eq!(
        running.has(Feature::Lzcnt),
        std::arch::is_x86_feature_detected!("lzcnt")
    );
    assert_eq!(
        running.has(Feature::Movbe),
        std::arch::is_x86_feature_detected!("movbe")
    );
}

/// A processor that is not x86 has none of the x86 instruction sets, and its target asks for none.
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
#[test]
fn a_processor_that_is_not_x86_has_none_of_the_instruction_sets() {
    assert_eq!(Features::running(), Features::of([]));
}

#[test]
fn instruction_sets_are_named_for_a_sentence() {
    assert_eq!(names(&[]), "");
    assert_eq!(names(&[Feature::Avx2]), "AVX2");
    assert_eq!(names(&[Feature::Avx2, Feature::Bmi2]), "AVX2 and BMI2");
    assert_eq!(
        names(&[Feature::Avx, Feature::Avx2, Feature::Bmi2]),
        "AVX, AVX2 and BMI2"
    );
}

// ---------------------------------------------------------------------------------------------
// The processor check cannot be folded away
// ---------------------------------------------------------------------------------------------

/// The processor check asks the processor, and the standard library answers a question about an
/// instruction set the build itself enabled with a constant yes. A daemon built that way would
/// start on a processor without the set and stop on it, the failure the check exists to prevent, so
/// the crate refuses to build when any instruction set of the baseline is enabled at compile time.
/// The control is the same source built with no flag; each refusal names what to remove.
///
/// This builds `src/processor.rs` alone with the compiler, on the host's own architecture.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[test]
fn a_build_that_enables_an_instruction_set_of_the_baseline_is_refused() {
    let source = concat!(env!("CARGO_MANIFEST_DIR"), "/src/processor.rs");
    let directory = tempfile::tempdir().expect("a directory");
    let build = |flags: &[String]| {
        std::process::Command::new("rustc")
            .args([
                "--edition",
                "2024",
                "--crate-type",
                "lib",
                "--emit=metadata",
            ])
            .arg("--out-dir")
            .arg(directory.path())
            .args(flags)
            .arg(source)
            .output()
            .expect("the compiler starts")
    };

    let control = build(&[]);
    assert!(
        control.status.success(),
        "the control builds: {}",
        String::from_utf8_lossy(&control.stderr)
    );
    for name in [
        "sse4.2", "popcnt", "avx", "avx2", "bmi1", "bmi2", "fma", "f16c", "lzcnt", "movbe",
    ] {
        let refused = build(&[format!("-Ctarget-feature=+{name}")]);
        let said = String::from_utf8_lossy(&refused.stderr);
        assert!(!refused.status.success(), "{name} was accepted");
        assert!(
            said.contains("built for the target's own instruction sets"),
            "{name}: {said}"
        );
        assert!(said.contains("target-feature"), "{name}: {said}");
    }
    let native = build(&["-Ctarget-cpu=native".to_owned()]);
    let said = String::from_utf8_lossy(&native.stderr);
    // A native build on a machine with none of the sets would be accepted, and no machine a release
    // is built on lacks AVX2, so this holds wherever the test runs.
    assert!(
        !native.status.success() || !std::arch::is_x86_feature_detected!("avx2"),
        "{said}"
    );
}

// ---------------------------------------------------------------------------------------------
// The build says the same thing
// ---------------------------------------------------------------------------------------------

/// The workspace's own build settings, which every build of the description process reads.
const BUILD_SETTINGS: &str = include_str!("../../../.cargo/config.toml");

/// The llama.cpp options the build leaves off, so that nothing wider than the baseline is compiled
/// in and nothing is taken from the machine that compiles.
const OPTIONS_LEFT_OFF: [&str; 9] = [
    "GGML_NATIVE",
    "GGML_AVX_VNNI",
    "GGML_AVX512",
    "GGML_AVX512_VBMI",
    "GGML_AVX512_VNNI",
    "GGML_AVX512_BF16",
    "GGML_AMX_TILE",
    "GGML_AMX_INT8",
    "GGML_AMX_BF16",
];

/// Every llama.cpp option the settings set for the build, and its value, as the settings say it.
///
/// An option that is set without being forced is not counted as set: an environment that already
/// holds it would win, and the baseline would be that environment's.
fn pinned(settings: &str) -> BTreeMap<String, String> {
    let document: toml_edit::DocumentMut = settings.parse().expect("the build settings parse");
    let mut pins = BTreeMap::new();
    let Some(environment) = document.get("env").and_then(|item| item.as_table_like()) else {
        return pins;
    };
    for (name, item) in environment.iter() {
        if !name.starts_with("GGML_") {
            continue;
        }
        let Some(table) = item.as_table_like() else {
            continue;
        };
        let forced = table
            .get("force")
            .and_then(|force| force.as_bool())
            .unwrap_or(false);
        let value = table
            .get("value")
            .and_then(|value| value.as_str())
            .map(str::to_owned);
        if let (true, Some(value)) = (forced, value) {
            pins.insert(name.to_owned(), value);
        }
    }
    pins
}

/// Where the build's pins differ from the baseline: an instruction set of the baseline that has an
/// option and is not on, an option that must be off and is not, and an option that is pinned and is
/// neither.
fn disagreements(pins: &BTreeMap<String, String>) -> Vec<String> {
    let mut found = Vec::new();
    for option in Feature::X86_64
        .iter()
        .filter_map(|feature| feature.build_option())
    {
        if pins.get(option).map(String::as_str) != Some("ON") {
            found.push(format!("{option} is not forced on"));
        }
    }
    for option in OPTIONS_LEFT_OFF {
        if pins.get(option).map(String::as_str) != Some("OFF") {
            found.push(format!("{option} is not forced off"));
        }
    }
    for option in pins.keys() {
        let known = OPTIONS_LEFT_OFF.contains(&option.as_str())
            || Feature::X86_64
                .iter()
                .any(|feature| feature.build_option() == Some(option.as_str()));
        if !known {
            found.push(format!(
                "{option} is pinned and is not part of the baseline"
            ));
        }
    }
    found
}

/// The build pins the instruction sets the baseline names and no others, and takes nothing from the
/// machine that compiles. The control is a settings file that leaves one out, a second that does
/// not force one, and a third that pins another, each of which is noticed.
#[test]
fn the_build_compiles_the_instruction_sets_the_baseline_names_and_no_others() {
    assert_eq!(
        disagreements(&pinned(BUILD_SETTINGS)),
        Vec::<String>::new(),
        "the workspace's build settings"
    );

    let complete = |left_out: &str, forced_off: &str, extra: &str| {
        let mut text = String::from("[env]\n");
        for option in Feature::X86_64
            .iter()
            .filter_map(|feature| feature.build_option())
        {
            if option != left_out {
                text.push_str(&format!("{option} = {{ value = \"ON\", force = true }}\n"));
            }
        }
        for option in OPTIONS_LEFT_OFF {
            let force = if option == forced_off {
                "false"
            } else {
                "true"
            };
            text.push_str(&format!(
                "{option} = {{ value = \"OFF\", force = {force} }}\n"
            ));
        }
        text.push_str(extra);
        text
    };
    assert_eq!(
        disagreements(&pinned(&complete("", "", ""))),
        Vec::<String>::new()
    );
    assert_eq!(
        disagreements(&pinned(&complete("GGML_BMI2", "", ""))),
        ["GGML_BMI2 is not forced on"]
    );
    assert_eq!(
        disagreements(&pinned(&complete("", "GGML_AVX512", ""))),
        ["GGML_AVX512 is not forced off"]
    );
    assert_eq!(
        disagreements(&pinned(&complete(
            "",
            "",
            "GGML_LLAMAFILE = { value = \"ON\", force = true }\n"
        ))),
        ["GGML_LLAMAFILE is pinned and is not part of the baseline"]
    );
}
