//! The signed model profile: what a host has to know before it maps a model.
//!
//! Section 22 puts a fixed list in the profile and nowhere else: *exact model/source revisions,
//! verified asset hashes/sizes, conversion/runtime revisions, tokenizer and chat-template hashes,
//! explicit sampler values, non-reasoning setting and compatible targets*, with zero GPU layers and
//! no tools or vision component. A profile is therefore not configuration. It is the statement a
//! qualification was made against, and every one of those fields is here because changing it
//! changes what was qualified.
//!
//! # What a signature buys, and what it does not
//!
//! A profile compiled into this binary is trusted exactly as far as the binary is: substituting it
//! means substituting the executable, which no signature inside the executable could detect.
//! [`Catalogue::builtin`] is that case, and it is the one this build ships.
//!
//! A profile that arrives from *outside* the binary is a different matter: an installed profile
//! directory is a file on disk somebody can replace. That one carries a detached signature over a
//! domain-separated transcript of its exact bytes, and [`ProfileTrust::verify`] is the only way to
//! turn it into a [`ModelProfile`]. There is no entry point that parses an unsigned profile from
//! bytes, because a host that could would eventually be asked to.
//!
//! Either way the asset digests are what protect the weights. The profile names the size and the
//! SHA-256 of every file, [`Asset::verify_file`] streams the file and refuses on either, and a
//! download that does not match is not used. That check is the same whether the profile came from
//! the binary or from a signature.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use kr_cbor::CanonicalValue;
use kr_crypto::sign::SigningTranscript;
use kr_protocol::scalars::{AuthorisationKey, Signature64};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::budget::ResidentCost;
use crate::error::{DescribeError, Result};

/// The domain every profile signature is separated by.
pub const PROFILE_SIGNING_DOMAIN: &str = "kr-describe/profile/1";

/// How many bytes an asset digest reads at a time.
///
/// A model file is gigabytes. It is hashed in fixed blocks so verifying one costs a buffer rather
/// than the file, on the 8 GiB host section 22 keeps supporting.
const DIGEST_BLOCK_BYTES: usize = 1 << 20;

/// A profile's revision.
///
/// It advances whenever anything in the profile changes, and it is what makes a late result
/// decidable: a result carries the revision it was produced under, and a host that has since
/// remapped refuses it rather than attributing the text to the profile it is now running.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct ProfileRevision(u64);

impl ProfileRevision {
    /// Wraps a raw revision.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the raw revision.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Whether a profile is the default or a candidate behind gates.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Gate {
    /// The qualified default. Selecting it needs nothing but a compatible target.
    Default,
    /// A candidate compatibility alternative. It is selectable only when every gate it lists has
    /// been met, and section 22 forbids pressure, a timeout or bad output from selecting it.
    Candidate,
}

/// A gate a candidate profile has to pass before it can be enabled.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualificationGate {
    /// The declared platform gate: the target is one this profile was qualified on.
    Platform,
    /// The declared resource gate: this host meets the profile's own resource statement.
    Resource,
    /// The declared quality gate: the profile passed the qualification matrix.
    Quality,
}

impl QualificationGate {
    /// Returns the stable name this gate is reported under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Platform => "platform",
            Self::Resource => "resource",
            Self::Quality => "quality",
        }
    }
}

/// The model this profile is of.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelIdentity {
    /// The repository the model comes from.
    pub repository: String,
    /// The exact model revision.
    pub model_revision: String,
    /// The exact source revision the model was published at.
    pub source_revision: String,
    /// The parameter count, in billions, as the publisher states it.
    pub parameters_billions: f64,
}

/// How the model was converted to the format the runtime loads.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConversionIdentity {
    /// The repository the converted asset was read from.
    pub repository: String,
    /// The exact revision of that repository the asset was read at.
    pub revision: String,
    /// The quantisation the conversion produced.
    pub quantisation: String,
    /// The container format.
    pub format: String,
}

/// The runtime this profile was qualified against.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeIdentity {
    /// The binding crate.
    pub binding: String,
    /// Its exact version.
    pub binding_version: String,
    /// The revision of the inference library that binding vendors.
    pub llama_cpp_revision: String,
}

/// One file a profile needs, with the size and digest that decide whether it is the right one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Asset {
    /// What the file is for.
    pub role: String,
    /// The file's name in the cache.
    pub file_name: String,
    /// Where it is fetched from, once, under the disclosed download policy.
    pub url: String,
    /// Its exact size.
    pub bytes: u64,
    /// Its SHA-256, lowercase hexadecimal.
    pub sha256: String,
}

impl Asset {
    /// Verifies a downloaded file against this asset's recorded size and digest.
    ///
    /// The size is checked first because it is free and it catches a truncated download without
    /// reading a gigabyte; the digest is then streamed. Neither is a warning: a file that fails
    /// either is not the file this profile was qualified against, and nothing loads it.
    ///
    /// # Errors
    ///
    /// Returns [`DescribeError::AssetSizeMismatch`] or [`DescribeError::AssetDigestMismatch`] when
    /// the file is not the recorded one, and [`DescribeError::AssetUnreadable`] when it cannot be
    /// read at all.
    pub fn verify_file(&self, path: &Path) -> Result<()> {
        let metadata = std::fs::metadata(path).map_err(|error| DescribeError::AssetUnreadable {
            file: self.file_name.clone(),
            detail: error.to_string(),
        })?;
        if metadata.len() != self.bytes {
            return Err(DescribeError::AssetSizeMismatch {
                file: self.file_name.clone(),
                expected: self.bytes,
                found: metadata.len(),
            });
        }
        let mut file = File::open(path).map_err(|error| DescribeError::AssetUnreadable {
            file: self.file_name.clone(),
            detail: error.to_string(),
        })?;
        let mut hasher = Sha256::new();
        let mut block = vec![0_u8; DIGEST_BLOCK_BYTES];
        loop {
            let read = file
                .read(&mut block)
                .map_err(|error| DescribeError::AssetUnreadable {
                    file: self.file_name.clone(),
                    detail: error.to_string(),
                })?;
            if read == 0 {
                break;
            }
            hasher.update(&block[..read]);
        }
        let found = hex_of(&hasher.finalize());
        if found != self.sha256.to_ascii_lowercase() {
            return Err(DescribeError::AssetDigestMismatch {
                file: self.file_name.clone(),
                expected: self.sha256.clone(),
                found,
            });
        }
        Ok(())
    }
}

/// The tokenizer and chat template this profile was qualified with.
///
/// Section 22: *do not share tokenizer/template defaults across models*. Each profile names its
/// own source, and [`Catalogue`] refuses a set in which two profiles carry the same tokenizer
/// digest, because that is what sharing one looks like from the outside.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenizerIdentity {
    /// The repository the tokenizer comes from.
    pub source_repository: String,
    /// The exact revision of that repository.
    pub source_revision: String,
    /// The tokenizer's SHA-256.
    pub tokenizer_sha256: String,
    /// The tokenizer configuration's SHA-256.
    pub tokenizer_config_sha256: String,
    /// The chat template's SHA-256.
    pub chat_template_sha256: String,
}

/// The sampler values, stated rather than defaulted.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamplerSettings {
    /// The sampling temperature. Nought is greedy decoding.
    pub temperature: f64,
    /// The top-k bound.
    pub top_k: u32,
    /// The nucleus bound.
    pub top_p: f64,
    /// The minimum-probability bound.
    pub min_p: f64,
    /// The repetition penalty.
    pub repeat_penalty: f64,
    /// How many recent tokens the repetition penalty looks back over.
    pub repeat_last_n: u32,
    /// The sampler seed. It is fixed so two runs of one qualification agree.
    pub seed: u32,
}

impl SamplerSettings {
    /// Returns whether decoding is greedy, which is what a temperature of nought means.
    #[must_use]
    pub fn is_greedy(&self) -> bool {
        self.temperature <= f64::EPSILON
    }
}

/// Whether the profile runs the model in a reasoning mode.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReasoningSetting {
    /// The mode. Only `disabled` is accepted: a title is not worth a chain of thought, and the
    /// output budget is 128 tokens.
    pub mode: String,
    /// The directive that turns reasoning off in this model's own chat template, when it has one.
    pub directive: Option<String>,
}

impl ReasoningSetting {
    /// Returns whether reasoning is off.
    #[must_use]
    pub fn is_disabled(&self) -> bool {
        self.mode == "disabled"
    }
}

/// Which optional components the profile has. Section 22 allows neither.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Components {
    /// Whether a tool-calling component is present.
    pub tools: bool,
    /// Whether a vision component is present.
    pub vision: bool,
}

/// How the profile is executed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionSettings {
    /// GPU layers. Section 22 keeps this at nought as the agreed CPU-only design.
    pub gpu_layers: u32,
    /// The context window, in tokens.
    pub context_tokens: u32,
    /// The output bound, in tokens.
    pub max_output_tokens: u32,
    /// How many CPU threads the runtime is given.
    pub cpu_threads: u32,
    /// The profile's own itemised estimate of what a resident model costs.
    ///
    /// It is the figure the reserve is checked against before anything is loaded, and it is
    /// deliberately larger than the asset: section 22 forbids reasoning from file size alone. A
    /// benchmark measures the same items again on real hardware, and the qualification note puts
    /// the two beside each other.
    pub resident_estimate: ResidentCost,
}

/// A model profile.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelProfile {
    profile_id: String,
    profile_revision: ProfileRevision,
    gate: Gate,
    model: ModelIdentity,
    conversion: ConversionIdentity,
    runtime: RuntimeIdentity,
    assets: Vec<Asset>,
    tokenizer: TokenizerIdentity,
    sampler: SamplerSettings,
    reasoning: ReasoningSetting,
    components: Components,
    execution: ExecutionSettings,
    targets: Vec<String>,
    gates: Vec<QualificationGate>,
}

impl ModelProfile {
    /// Parses a profile from its document bytes and checks the invariants section 22 fixes.
    ///
    /// The invariants are checked here rather than by the caller because a profile that broke one
    /// of them would be a profile this product must not run, whoever loaded it: zero GPU layers,
    /// no tools, no vision, reasoning off, at least one asset, and a default profile with no gates
    /// left to pass.
    ///
    /// # Errors
    ///
    /// Returns [`DescribeError::ProfileMalformed`] when the document does not parse and
    /// [`DescribeError::ProfileRefused`] when it parses and states something this product will not
    /// run.
    pub fn parse(document: &[u8]) -> Result<Self> {
        let profile: Self =
            serde_json::from_slice(document).map_err(|error| DescribeError::ProfileMalformed {
                detail: error.to_string(),
            })?;
        profile.check()?;
        Ok(profile)
    }

    fn check(&self) -> Result<()> {
        let refuse = |why: &'static str| {
            Err(DescribeError::ProfileRefused {
                profile: self.profile_id.clone(),
                why,
            })
        };
        if self.profile_id.is_empty() {
            return refuse("a profile with no identifier");
        }
        if self.execution.gpu_layers != 0 {
            return refuse("GPU layers, where section 22 fixes zero");
        }
        if self.components.tools || self.components.vision {
            return refuse("a tools or vision component, which the profile has none of");
        }
        if !self.reasoning.is_disabled() {
            return refuse("reasoning, which is off in every profile");
        }
        if self.assets.is_empty() {
            return refuse("no assets to verify");
        }
        if self.targets.is_empty() {
            return refuse("no compatible targets");
        }
        if matches!(self.gate, Gate::Default) && !self.gates.is_empty() {
            return refuse("the default gate with gates still to pass");
        }
        if matches!(self.gate, Gate::Candidate) && self.gates.is_empty() {
            return refuse("the candidate gate with no gates to pass");
        }
        if self.execution.resident_estimate.weights_bytes != self.asset_bytes() {
            return refuse("a weights estimate that is not the size of its own assets");
        }
        if self.execution.resident_estimate.beyond_the_weights() == 0 {
            return refuse("a resident estimate that is its file size alone");
        }
        Ok(())
    }

    /// Returns the profile's identifier.
    #[must_use]
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    /// Returns the profile's revision.
    #[must_use]
    pub const fn revision(&self) -> ProfileRevision {
        self.profile_revision
    }

    /// Returns whether this is the default profile or a gated candidate.
    #[must_use]
    pub const fn gate(&self) -> Gate {
        self.gate
    }

    /// Returns the gates a candidate has still to pass.
    #[must_use]
    pub fn gates(&self) -> &[QualificationGate] {
        &self.gates
    }

    /// Returns the model identity.
    #[must_use]
    pub const fn model(&self) -> &ModelIdentity {
        &self.model
    }

    /// Returns the conversion identity.
    #[must_use]
    pub const fn conversion(&self) -> &ConversionIdentity {
        &self.conversion
    }

    /// Returns the runtime identity.
    #[must_use]
    pub const fn runtime(&self) -> &RuntimeIdentity {
        &self.runtime
    }

    /// Returns the assets this profile needs.
    #[must_use]
    pub fn assets(&self) -> &[Asset] {
        &self.assets
    }

    /// Returns the total size of this profile's assets, which is what one download costs.
    #[must_use]
    pub fn asset_bytes(&self) -> u64 {
        self.assets.iter().map(|asset| asset.bytes).sum()
    }

    /// Returns the tokenizer identity.
    #[must_use]
    pub const fn tokenizer(&self) -> &TokenizerIdentity {
        &self.tokenizer
    }

    /// Returns the sampler values.
    #[must_use]
    pub const fn sampler(&self) -> &SamplerSettings {
        &self.sampler
    }

    /// Returns the reasoning setting.
    #[must_use]
    pub const fn reasoning(&self) -> &ReasoningSetting {
        &self.reasoning
    }

    /// Returns which optional components the profile has, which is none of them.
    #[must_use]
    pub const fn components(&self) -> &Components {
        &self.components
    }

    /// Returns the execution settings.
    #[must_use]
    pub const fn execution(&self) -> &ExecutionSettings {
        &self.execution
    }

    /// Returns the targets this profile was qualified on.
    #[must_use]
    pub fn targets(&self) -> &[String] {
        &self.targets
    }

    /// Returns whether the profile lists a target.
    #[must_use]
    pub fn supports_target(&self, target: &str) -> bool {
        self.targets.iter().any(|listed| listed == target)
    }
}

/// A profile document as bytes, with the digest those exact bytes have.
///
/// The digest is of the file rather than of a re-encoding, so a document whose formatting changed
/// without its content changing is still a different document. That is the point: what was
/// qualified is a file, and a host that re-encoded before hashing would accept a file nobody
/// qualified as long as it happened to mean the same thing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileDocument {
    bytes: Vec<u8>,
    digest: [u8; 32],
}

impl ProfileDocument {
    /// Takes a document's bytes.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        let digest = kr_cbor::sha256(&bytes);
        Self { bytes, digest }
    }

    /// Returns the exact bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the document's SHA-256.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Returns the document's SHA-256 in lowercase hexadecimal, which is how it is recorded in
    /// provenance.
    #[must_use]
    pub fn digest_hex(&self) -> String {
        hex_of(&self.digest)
    }

    /// Builds the transcript a signature over this document covers.
    ///
    /// The identifier and the revision are covered beside the digest so a signature over one
    /// profile cannot be presented for another that happens to have the same bytes under a
    /// different name.
    ///
    /// # Errors
    ///
    /// Returns [`DescribeError::ProfileMalformed`] when the document does not parse far enough to
    /// name itself.
    pub fn transcript(&self) -> Result<SigningTranscript> {
        let profile = ModelProfile::parse(&self.bytes)?;
        let revision =
            CanonicalValue::integer(i128::from(profile.revision().get())).map_err(|error| {
                DescribeError::ProfileMalformed {
                    detail: error.to_string(),
                }
            })?;
        Ok(SigningTranscript::from_elements(
            PROFILE_SIGNING_DOMAIN,
            vec![
                CanonicalValue::Text(profile.profile_id().to_owned()),
                revision,
                CanonicalValue::Bytes(self.digest.to_vec()),
            ],
        ))
    }
}

/// A profile document with a detached signature over it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedProfile {
    /// The document.
    pub document: ProfileDocument,
    /// The key the signature is claimed to be from.
    pub key: AuthorisationKey,
    /// The signature.
    pub signature: Signature64,
}

/// The keys a host accepts a profile signature from.
///
/// An empty trust set accepts nothing, which is the right answer for a host that has not been
/// given a key: a profile from an unknown signer is refused rather than trusted for want of an
/// alternative.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProfileTrust {
    keys: Vec<AuthorisationKey>,
}

impl ProfileTrust {
    /// Builds a trust set from the keys a host accepts.
    #[must_use]
    pub fn new(keys: Vec<AuthorisationKey>) -> Self {
        Self { keys }
    }

    /// Returns how many keys this host accepts profiles from.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Returns whether this host accepts no profile signature at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Verifies a signed profile and returns it.
    ///
    /// This is the only way a profile from outside the binary becomes a [`ModelProfile`].
    ///
    /// # Errors
    ///
    /// Returns [`DescribeError::ProfileUntrustedKey`] when the signing key is not one this host
    /// accepts, [`DescribeError::ProfileSignatureInvalid`] when the signature does not verify over
    /// the document, and the parse or refusal errors when the document itself is not one this
    /// product will run.
    pub fn verify(&self, signed: &SignedProfile) -> Result<ModelProfile> {
        if !self.keys.iter().any(|key| key == &signed.key) {
            return Err(DescribeError::ProfileUntrustedKey);
        }
        let transcript = signed.document.transcript()?;
        kr_crypto::sign::verify(&signed.key, &transcript, &signed.signature)
            .map_err(|_| DescribeError::ProfileSignatureInvalid)?;
        ModelProfile::parse(signed.document.bytes())
    }
}

/// Renders bytes as lowercase hexadecimal.
fn hex_of(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    out
}

/// The profiles this build ships, and the rules for choosing between them.
pub mod catalogue {
    use super::{DescribeError, Gate, ModelProfile, ProfileRevision, QualificationGate, Result};

    /// The default profile's document, compiled into this binary.
    pub const DEFAULT_PROFILE_DOCUMENT: &str = include_str!("../profiles/minicpm5-2b-q4-k-m.json");

    /// The gated candidate's document, compiled into this binary.
    pub const CANDIDATE_PROFILE_DOCUMENT: &str = include_str!("../profiles/smollm3-3b-q4-k-m.json");

    /// Why a profile was not selected.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum NotSelected {
        /// The profile does not list this target.
        IncompatibleTarget,
        /// The profile is a candidate and these gates have not been met on this host.
        GatesOutstanding(Vec<QualificationGate>),
    }

    /// What selecting a profile decided.
    #[derive(Clone, Debug, PartialEq)]
    pub enum Selection {
        /// This profile is selected.
        ///
        /// It is boxed because a profile is far larger than the refusal beside it, and a value
        /// this size copied on every read of the selection would be paid for by every caller.
        Profile(Box<ModelProfile>),
        /// No profile is selected, and deterministic metadata is what this host shows. It is the
        /// always-available fallback, not a degraded mode.
        DeterministicMetadata {
            /// Why each profile was not selected, in catalogue order.
            reasons: Vec<(String, NotSelected)>,
        },
    }

    impl Selection {
        /// Returns the selected profile, when one was selected.
        #[must_use]
        pub const fn profile(&self) -> Option<&ModelProfile> {
            match self {
                Self::Profile(profile) => Some(profile),
                Self::DeterministicMetadata { .. } => None,
            }
        }
    }

    /// Which gates an owner has recorded as met on this host.
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct MetGates(Vec<QualificationGate>);

    impl MetGates {
        /// Records the gates an owner has met.
        #[must_use]
        pub fn new(met: Vec<QualificationGate>) -> Self {
            Self(met)
        }

        /// Returns whether a gate is met.
        #[must_use]
        pub fn has(&self, gate: QualificationGate) -> bool {
            self.0.contains(&gate)
        }

        /// Returns the gates a profile still needs.
        #[must_use]
        pub fn outstanding(&self, profile: &ModelProfile) -> Vec<QualificationGate> {
            profile
                .gates()
                .iter()
                .copied()
                .filter(|gate| !self.has(*gate))
                .collect()
        }
    }

    /// The profiles this host can choose between.
    #[derive(Clone, Debug, PartialEq)]
    pub struct Catalogue {
        profiles: Vec<ModelProfile>,
    }

    impl Catalogue {
        /// Builds the catalogue this build ships.
        ///
        /// # Errors
        ///
        /// Returns a parse or refusal error when a shipped profile is not one this product will
        /// run, which is a fault in this build rather than in the host.
        pub fn builtin() -> Result<Self> {
            Self::new(vec![
                ModelProfile::parse(DEFAULT_PROFILE_DOCUMENT.as_bytes())?,
                ModelProfile::parse(CANDIDATE_PROFILE_DOCUMENT.as_bytes())?,
            ])
        }

        /// Builds a catalogue from profiles that have already been parsed or verified.
        ///
        /// # Errors
        ///
        /// Returns [`DescribeError::CatalogueRefused`] when the set breaks one of section 22's
        /// rules about the set rather than about a profile: exactly one default, no repeated
        /// identifier, and no tokenizer or chat template shared between two models.
        pub fn new(profiles: Vec<ModelProfile>) -> Result<Self> {
            let defaults = profiles
                .iter()
                .filter(|profile| matches!(profile.gate(), Gate::Default))
                .count();
            if defaults != 1 {
                return Err(DescribeError::CatalogueRefused {
                    why: "a catalogue names exactly one default profile",
                });
            }
            for (index, profile) in profiles.iter().enumerate() {
                for other in &profiles[index + 1..] {
                    if profile.profile_id() == other.profile_id() {
                        return Err(DescribeError::CatalogueRefused {
                            why: "two profiles with one identifier",
                        });
                    }
                    if profile.model().repository != other.model().repository
                        && (profile.tokenizer().tokenizer_sha256
                            == other.tokenizer().tokenizer_sha256
                            || profile.tokenizer().chat_template_sha256
                                == other.tokenizer().chat_template_sha256)
                    {
                        return Err(DescribeError::CatalogueRefused {
                            why: "a tokenizer or chat template shared between two models",
                        });
                    }
                }
            }
            Ok(Self { profiles })
        }

        /// Returns the profiles, in catalogue order.
        #[must_use]
        pub fn profiles(&self) -> &[ModelProfile] {
            &self.profiles
        }

        /// Returns the default profile.
        #[must_use]
        pub fn default_profile(&self) -> &ModelProfile {
            self.profiles
                .iter()
                .find(|profile| matches!(profile.gate(), Gate::Default))
                .unwrap_or_else(|| {
                    unreachable!("a catalogue is built with exactly one default profile")
                })
        }

        /// Returns a profile by identifier.
        #[must_use]
        pub fn profile(&self, profile_id: &str) -> Option<&ModelProfile> {
            self.profiles
                .iter()
                .find(|profile| profile.profile_id() == profile_id)
        }

        /// Chooses the profile this host runs.
        ///
        /// The rule has one shape and no exceptions. The default is chosen when this target is one
        /// it was qualified on. A candidate is chosen only when the owner has recorded every gate
        /// it declares, which is what *may be enabled only after meeting the same declared
        /// platform/resource/quality gates* means. When neither answers, the answer is
        /// deterministic metadata.
        ///
        /// Nothing about the host's *condition* reaches this function: there is no memory figure,
        /// no timeout, no previous failure and no output quality in its arguments. That is section
        /// 22's rule that pressure, a timeout or bad output never selects a different model,
        /// expressed as an absence rather than as a branch somebody could add.
        #[must_use]
        pub fn select(&self, target: &str, met: &MetGates) -> Selection {
            let mut reasons = Vec::new();
            for profile in &self.profiles {
                if !profile.supports_target(target) {
                    reasons.push((
                        profile.profile_id().to_owned(),
                        NotSelected::IncompatibleTarget,
                    ));
                    continue;
                }
                let outstanding = met.outstanding(profile);
                if outstanding.is_empty() {
                    return Selection::Profile(Box::new(profile.clone()));
                }
                reasons.push((
                    profile.profile_id().to_owned(),
                    NotSelected::GatesOutstanding(outstanding),
                ));
            }
            Selection::DeterministicMetadata { reasons }
        }

        /// Returns whether a result produced under a profile revision is still current.
        #[must_use]
        pub fn is_current(&self, profile_id: &str, revision: ProfileRevision) -> bool {
            self.profile(profile_id)
                .is_some_and(|profile| profile.revision() == revision)
        }
    }
}

/// What downloading a selected profile's assets is allowed to do.
///
/// Section 22: *download each selected profile once, under a disclosed download policy; never
/// download/map both merely to create a session*. The policy is a value rather than a convention,
/// so the size a person is shown before agreeing is the size that is then fetched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DownloadPolicy {
    /// The profile the disclosure was made for.
    pub profile_id: String,
    /// The revision it was made at.
    pub revision: ProfileRevision,
    /// The exact number of bytes that will be fetched, which is the sum of the profile's assets.
    pub bytes: u64,
    /// The hosts the fetch reaches.
    pub sources: Vec<String>,
}

impl DownloadPolicy {
    /// Builds the disclosure for one profile.
    #[must_use]
    pub fn of(profile: &ModelProfile) -> Self {
        let mut sources: Vec<String> = profile
            .assets()
            .iter()
            .filter_map(|asset| {
                asset
                    .url
                    .split_once("://")
                    .and_then(|(_, rest)| rest.split('/').next())
                    .map(str::to_owned)
            })
            .collect();
        sources.sort();
        sources.dedup();
        Self {
            profile_id: profile.profile_id().to_owned(),
            revision: profile.revision(),
            bytes: profile.asset_bytes(),
            sources,
        }
    }
}

/// What one environment has downloaded, and what it may still download.
///
/// One download per selected profile is enforced by recording it: a second request for a profile
/// this environment already holds is answered from the cache, and a request for a profile that is
/// not the selected one is refused outright rather than queued behind a disclosure nobody made.
#[derive(Debug, Default)]
pub struct DownloadLedger {
    downloaded: Vec<(String, ProfileRevision)>,
}

impl DownloadLedger {
    /// Builds an empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns whether a profile revision has already been downloaded.
    #[must_use]
    pub fn holds(&self, profile_id: &str, revision: ProfileRevision) -> bool {
        self.downloaded
            .iter()
            .any(|(id, held)| id == profile_id && *held == revision)
    }

    /// Returns how many downloads this environment has made.
    #[must_use]
    pub fn downloads(&self) -> usize {
        self.downloaded.len()
    }

    /// Admits a download of the selected profile, or says why not.
    ///
    /// # Errors
    ///
    /// Returns [`DescribeError::DownloadNotSelected`] when the profile asked for is not the one
    /// this environment selected.
    pub fn admit(
        &mut self,
        selected: &ModelProfile,
        asked_for: &ModelProfile,
    ) -> Result<Admission> {
        if selected.profile_id() != asked_for.profile_id()
            || selected.revision() != asked_for.revision()
        {
            return Err(DescribeError::DownloadNotSelected {
                selected: selected.profile_id().to_owned(),
                asked_for: asked_for.profile_id().to_owned(),
            });
        }
        if self.holds(asked_for.profile_id(), asked_for.revision()) {
            return Ok(Admission::AlreadyHeld);
        }
        self.downloaded
            .push((asked_for.profile_id().to_owned(), asked_for.revision()));
        Ok(Admission::Download(DownloadPolicy::of(asked_for)))
    }
}

/// What a download request was answered with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Admission {
    /// This environment already holds the assets; nothing is fetched.
    AlreadyHeld,
    /// A fetch is admitted, under exactly this disclosure.
    Download(DownloadPolicy),
}
