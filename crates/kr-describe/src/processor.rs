//! What the description process needs of a processor, and what this processor has.
//!
//! The description process runs llama.cpp's CPU backend, whose vector code is compiled for a fixed
//! set of x86-64 instruction sets and chosen at build time, not at run time: a processor without
//! one of them stops that process with an illegal instruction the first time it loads a model. The
//! set is the build's own and is written down here, once. The build reads the same set from the
//! environment `.cargo/config.toml` gives it (each [`Feature`] names the llama.cpp option that
//! turns it on), a test holds the two equal, and the build refuses to take the set from the machine
//! that compiles it.
//!
//! A host checks the processor it runs on against that set when it selects a profile, so a
//! processor without the instructions is offered no model and shows a reason, and the description
//! process is never started on it. A target that is not x86-64 asks for nothing here: its CPU code
//! is chosen by the target itself.

use std::collections::BTreeSet;

/// An x86-64 instruction set the description process's build needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Feature {
    /// SSE4.2.
    Sse42,
    /// AVX.
    Avx,
    /// AVX2.
    Avx2,
    /// BMI2.
    Bmi2,
    /// Fused multiply-add.
    Fma,
    /// Half-precision conversion.
    F16c,
}

impl Feature {
    /// Every instruction set the build needs on an x86-64 target.
    pub const X86_64: [Self; 6] = [
        Self::Sse42,
        Self::Avx,
        Self::Avx2,
        Self::Bmi2,
        Self::Fma,
        Self::F16c,
    ];

    /// Returns the name a person knows it by.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sse42 => "SSE4.2",
            Self::Avx => "AVX",
            Self::Avx2 => "AVX2",
            Self::Bmi2 => "BMI2",
            Self::Fma => "FMA",
            Self::F16c => "F16C",
        }
    }

    /// Returns the llama.cpp build option that compiles its CPU code for this instruction set.
    #[must_use]
    pub const fn build_option(self) -> &'static str {
        match self {
            Self::Sse42 => "GGML_SSE42",
            Self::Avx => "GGML_AVX",
            Self::Avx2 => "GGML_AVX2",
            Self::Bmi2 => "GGML_BMI2",
            Self::Fma => "GGML_FMA",
            Self::F16c => "GGML_F16C",
        }
    }

    /// Returns whether the processor this is running on has it.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn running(self) -> bool {
        match self {
            Self::Sse42 => std::arch::is_x86_feature_detected!("sse4.2"),
            Self::Avx => std::arch::is_x86_feature_detected!("avx"),
            Self::Avx2 => std::arch::is_x86_feature_detected!("avx2"),
            Self::Bmi2 => std::arch::is_x86_feature_detected!("bmi2"),
            Self::Fma => std::arch::is_x86_feature_detected!("fma"),
            Self::F16c => std::arch::is_x86_feature_detected!("f16c"),
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

/// Names instruction sets for a sentence: `AVX2`, `AVX2 and BMI2`, `AVX, AVX2 and BMI2`.
#[must_use]
pub fn names(features: &[Feature]) -> String {
    match features {
        [] => String::new(),
        [only] => only.as_str().to_owned(),
        [first @ .., last] => format!(
            "{} and {}",
            first
                .iter()
                .map(|feature| feature.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            last.as_str()
        ),
    }
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
