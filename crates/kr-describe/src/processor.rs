//! What the description process needs of a processor, and what this processor has.
//!
//! The description process runs llama.cpp's CPU backend, whose vector code is compiled for a fixed
//! set of x86-64 instruction sets and chosen at build time, not at run time: a processor without
//! one of them stops that process with an illegal instruction the first time it loads a model. The
//! set is the build's own and is written down here, once. It is the x86-64-v3 level as compiled
//! code uses it. Six of its members have a llama.cpp option, which `.cargo/config.toml` pins on
//! (each [`Feature`] names its option, a test holds the two equal, and the build refuses to take
//! the set from the machine that compiles it). The other four have none: the compilers add POPCNT
//! with SSE4.2, and the scalar BMI instructions, LZCNT and MOVBE with the AVX2 level. Every
//! processor that has the six has those four, but a hypervisor can hide any instruction set on its
//! own, so a host checks all ten.
//!
//! A host checks the processor it runs on against that set when it selects a profile, so a
//! processor without the instructions is offered no model and shows a reason, and the description
//! process is never started on it. A target that is not x86-64 asks for nothing here: its CPU code
//! is chosen by the target itself.
//!
//! The check asks the processor, and the standard library answers a question about an instruction
//! set that the build itself enabled with a constant yes. A build that enables one is also one that
//! would start on a processor without it and stop there, so this crate refuses to build that way.

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    any(
        target_feature = "sse4.2",
        target_feature = "popcnt",
        target_feature = "avx",
        target_feature = "avx2",
        target_feature = "bmi1",
        target_feature = "bmi2",
        target_feature = "fma",
        target_feature = "f16c",
        target_feature = "lzcnt",
        target_feature = "movbe",
    )
))]
compile_error!(
    "this crate is built for the target's own instruction sets, so that the daemon starts on a \
     processor without the description process's baseline (SSE4.2, POPCNT, AVX, AVX2, BMI1, BMI2, \
     FMA, F16C, LZCNT and MOVBE) and says so: remove the `target-cpu` flag or the `target-feature` \
     flag that enables one of them"
);

use std::collections::BTreeSet;

/// An x86-64 instruction set the description process's build needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Feature {
    /// SSE4.2.
    Sse42,
    /// The population count instruction, which compilers add with SSE4.2.
    Popcnt,
    /// AVX.
    Avx,
    /// AVX2.
    Avx2,
    /// The scalar bit instructions of BMI1, which the AVX2 level brings with it.
    Bmi1,
    /// BMI2.
    Bmi2,
    /// Fused multiply-add.
    Fma,
    /// Half-precision conversion.
    F16c,
    /// The leading-zero count instruction, which the AVX2 level brings with it.
    Lzcnt,
    /// The byte-swapping move, which the AVX2 level brings with it.
    Movbe,
}

impl Feature {
    /// Every instruction set the build needs on an x86-64 target.
    pub const X86_64: [Self; 10] = [
        Self::Sse42,
        Self::Popcnt,
        Self::Avx,
        Self::Avx2,
        Self::Bmi1,
        Self::Bmi2,
        Self::Fma,
        Self::F16c,
        Self::Lzcnt,
        Self::Movbe,
    ];

    /// Returns the name a person knows it by.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sse42 => "SSE4.2",
            Self::Popcnt => "POPCNT",
            Self::Avx => "AVX",
            Self::Avx2 => "AVX2",
            Self::Bmi1 => "BMI1",
            Self::Bmi2 => "BMI2",
            Self::Fma => "FMA",
            Self::F16c => "F16C",
            Self::Lzcnt => "LZCNT",
            Self::Movbe => "MOVBE",
        }
    }

    /// Returns the llama.cpp build option that compiles its CPU code for this instruction set, or
    /// none when the compilers add the set themselves and llama.cpp has no option for it.
    #[must_use]
    pub const fn build_option(self) -> Option<&'static str> {
        match self {
            Self::Sse42 => Some("GGML_SSE42"),
            Self::Avx => Some("GGML_AVX"),
            Self::Avx2 => Some("GGML_AVX2"),
            Self::Bmi2 => Some("GGML_BMI2"),
            Self::Fma => Some("GGML_FMA"),
            Self::F16c => Some("GGML_F16C"),
            Self::Popcnt | Self::Bmi1 | Self::Lzcnt | Self::Movbe => None,
        }
    }

    /// Returns whether the processor this is running on has it.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn running(self) -> bool {
        match self {
            Self::Sse42 => std::arch::is_x86_feature_detected!("sse4.2"),
            Self::Popcnt => std::arch::is_x86_feature_detected!("popcnt"),
            Self::Avx => std::arch::is_x86_feature_detected!("avx"),
            Self::Avx2 => std::arch::is_x86_feature_detected!("avx2"),
            Self::Bmi1 => std::arch::is_x86_feature_detected!("bmi1"),
            Self::Bmi2 => std::arch::is_x86_feature_detected!("bmi2"),
            Self::Fma => std::arch::is_x86_feature_detected!("fma"),
            Self::F16c => std::arch::is_x86_feature_detected!("f16c"),
            Self::Lzcnt => std::arch::is_x86_feature_detected!("lzcnt"),
            Self::Movbe => std::arch::is_x86_feature_detected!("movbe"),
        }
    }

    /// Returns whether the processor this is running on has it: no other architecture has an
    /// x86-64 instruction set.
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    const fn running(self) -> bool {
        false
    }
}

/// Returns the instruction sets the description process built for `target` needs, which are none
/// for a target that is not x86-64.
#[must_use]
pub fn baseline(target: &str) -> &'static [Feature] {
    if target.starts_with("x86_64-") {
        &Feature::X86_64
    } else {
        &[]
    }
}

/// Returns the pieces of a sentence that names instruction sets: `AVX2`, `AVX2 and BMI2`,
/// `AVX, AVX2 and BMI2`. Each piece is a literal of this build, so a diagnostic that takes only
/// literals can carry them.
#[must_use]
pub fn name_parts(features: &[Feature]) -> Vec<&'static str> {
    let mut parts = Vec::with_capacity(features.len() * 2);
    for (index, feature) in features.iter().enumerate() {
        if index > 0 {
            parts.push(if index + 1 == features.len() {
                " and "
            } else {
                ", "
            });
        }
        parts.push(feature.as_str());
    }
    parts
}

/// Names instruction sets for a sentence: `AVX2`, `AVX2 and BMI2`, `AVX, AVX2 and BMI2`.
#[must_use]
pub fn names(features: &[Feature]) -> String {
    name_parts(features).concat()
}

/// The instruction sets a processor has, of those a build can need.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Features(BTreeSet<Feature>);

impl Features {
    /// Asks the processor this is running on, which is what a host's selection is made against.
    #[must_use]
    pub fn running() -> Self {
        Self(
            Feature::X86_64
                .into_iter()
                .filter(|feature| feature.running())
                .collect(),
        )
    }

    /// Says what a processor has.
    #[must_use]
    pub fn of(features: impl IntoIterator<Item = Feature>) -> Self {
        Self(features.into_iter().collect())
    }

    /// Returns whether it has `feature`.
    #[must_use]
    pub fn has(&self, feature: Feature) -> bool {
        self.0.contains(&feature)
    }

    /// Returns the instruction sets the description process built for `target` needs and this
    /// processor does not have, in the baseline's order.
    #[must_use]
    pub fn lacking(&self, target: &str) -> Vec<Feature> {
        baseline(target)
            .iter()
            .copied()
            .filter(|feature| !self.has(*feature))
            .collect()
    }
}
