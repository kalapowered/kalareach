//! The signed model profile: what a host has to know before it maps a model.
//!
//! Section 22 puts a fixed list in the profile and nowhere else: *exact model/source revisions,
//! verified asset hashes/sizes, conversion/runtime revisions, tokenizer and chat-template hashes,
//! explicit sampler values, non-reasoning setting and compatible targets*, with zero GPU layers and
//! no tools or vision component. A profile is therefore not configuration. It is the statement a
//! qualification was made against, and every one of those fields is here because changing it
//! changes what was qualified.
//!
//! # There is one way to get a [`ModelProfile`]
//!
//! [`ProfileTrust::verify`], over a document and a detached signature from a key this host accepts.
//! Nothing else in this module returns one: a document's fields are a private type, so there is no
//! `serde` path that produces an unchecked profile and no public constructor that skips the trust
//! set.
//!
//! The profiles this build ships go through the same door. `profiles/*.json` are compiled in beside
//! their detached signatures and the public half of the key that made them, and
//! [`catalogue::Catalogue::builtin`] verifies each one before it is used.
//!
//! # What that signature is worth, exactly
//!
//! Against a document that arrives from **outside** the binary - an installed profile directory, a
//! file somebody put on disk - it is worth what a signature is normally worth: the document was
//! made by the holder of this build's profile-signing key and has not changed since.
//!
//! Against the **built-in** documents it is worth less, and pretending otherwise would be the
//! dishonest part. The anchor is compiled in beside them, so replacing a built-in profile means
//! rebuilding, and a rebuild can carry a new anchor. What it buys is that there is one code path
//! rather than two, so the external case cannot rot while the built-in case is the one that runs.
//!
//! The profile-signing key is per build: it is generated, used to sign the documents, and not
//! retained. Changing a shipped profile therefore means generating a key, signing the documents
//! again and committing the anchor beside them, in one change. Installer signing is a separate key
//! and a separate concern.
//!
//! # What actually protects the weights
//!
//! The asset digests. The profile names the size and the SHA-256 of every file,
//! [`Asset::verify_file`] reads both from one open handle and refuses on either, and a download
//! that does not match is not used. That is the check that stands between this product and a
//! substituted model, and it is the same check whatever the profile came from.

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

/// The longest identity string a profile may carry.
///
/// A repository name, a commit, a quantisation and a target triple are all short. The bound is
/// here so a document cannot carry a megabyte of text in a field a person is shown.
const MAX_IDENTITY_LEN: usize = 256;

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
    /// A candidate compatibility alternative. It is selectable only when every gate section 22
    /// names has been met on this host, and pressure, a timeout or bad output never selects it.
    Candidate,
}

/// A gate a candidate profile has to pass before it can be enabled.
///
/// Section 22: a candidate *may be enabled only after meeting the same declared
/// platform/resource/quality gates*. All three, which is why [`QualificationGate::ALL`] exists and
/// why a candidate profile that declared fewer is refused.
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
    /// The three gates section 22 names, which every candidate declares.
    pub const ALL: &'static [Self] = &[Self::Platform, Self::Resource, Self::Quality];

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

/// The source model this profile is of.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelIdentity {
    /// The repository the source model comes from.
    pub repository: String,
    /// That repository's exact commit.
    ///
    /// This is the *source* revision: the model as its publisher released it, before any
    /// conversion. The converted asset's own revision is in [`ConversionIdentity`].
    pub revision: String,
    /// The parameter count, in billions, as the publisher states it.
    pub parameters_billions: f64,
}

/// How the model was converted to the format the runtime loads.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConversionIdentity {
    /// The repository the converted asset was read from.
    pub repository: String,
    /// That repository's exact commit.
    ///
    /// This identifies the *publication* of the converted asset. It is not a converter revision,
    /// and the field below says so rather than letting this one stand in for one.
    pub revision: String,
    /// The revision of the tool that performed the conversion, when the publisher records one.
    ///
    /// Neither profile this build ships has one: the publishers of these GGUF files do not state
    /// which converter produced them. Recording nothing says so. What binds the asset to this
    /// profile is its digest, not a converter this product cannot see.
    pub converter_revision: Option<String>,
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
    /// The file is opened once and both the size and the digest come from that one handle, so
    /// there is no window in which the name could be made to reach a different file between the
    /// two questions. Neither answer is a warning: a file that fails either is not the file this
    /// profile was qualified against, and nothing loads it.
    ///
    /// What this cannot do is hand the caller the handle it verified, so a loader that opens the
    /// path again is trusting that nothing replaced the file in between. Where the cache is the
    /// owner's own directory that is the trust the cache already needs.
    ///
    /// # Errors
    ///
    /// Returns [`DescribeError::AssetSizeMismatch`] or [`DescribeError::AssetDigestMismatch`] when
    /// the file is not the recorded one, and [`DescribeError::AssetUnreadable`] when it cannot be
    /// read at all.
    pub fn verify_file(&self, path: &Path) -> Result<()> {
        let unreadable = |error: std::io::Error| DescribeError::AssetUnreadable {
            file: self.file_name.clone(),
            detail: error.to_string(),
        };
        let mut file = File::open(path).map_err(unreadable)?;
        let found_bytes = file.metadata().map_err(unreadable)?.len();
        if found_bytes != self.bytes {
            return Err(DescribeError::AssetSizeMismatch {
                file: self.file_name.clone(),
                expected: self.bytes,
                found: found_bytes,
            });
        }
        let mut hasher = Sha256::new();
        let mut block = vec![0_u8; DIGEST_BLOCK_BYTES];
        loop {
            let read = file.read(&mut block).map_err(unreadable)?;
            if read == 0 {
                break;
            }
            hasher.update(&block[..read]);
        }
        let found = hex_of(&hasher.finalize());
        if found != self.sha256 {
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
/// Section 22: *do not share tokenizer/template defaults across models*. Each profile names its own
/// source repository and revision and the digests of the files there, so a profile that borrowed
/// another model's defaults would be one whose tokenizer source is not its own model's.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenizerIdentity {
    /// The repository the tokenizer comes from.
    pub source_repository: String,
    /// The exact revision of that repository.
    pub source_revision: String,
    /// The source tokenizer's SHA-256.
    pub tokenizer_sha256: String,
    /// The source tokenizer configuration's SHA-256.
    pub tokenizer_config_sha256: String,
    /// The source chat template's SHA-256.
    pub chat_template_sha256: String,
    /// Whether the tokenizer and template the profile is about are **embedded in the asset**.
    ///
    /// It is true for every profile here, and it is what makes the three digests above provenance
    /// rather than the thing inference reads. A GGUF carries its own tokenizer and chat template,
    /// and those are bound by the asset digest; a publisher that regenerated the template during
    /// conversion has an embedded template whose bytes are not the source file's, and the asset
    /// digest is what pins it.
    ///
    /// The tokenizer is the one inference uses: the runtime tokenizes through the model's own
    /// vocabulary. The chat template is **not** applied by this build, which sends the instruction
    /// and the data section as a plain prompt. The digest is recorded so a profile that changed
    /// its template is a different profile, and applying the template - with the reasoning
    /// directive beside it - is named in this crate's documentation as work this build does not
    /// do.
    pub embedded_in_asset: bool,
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

    /// Returns whether every value is inside the range the runtime accepts.
    fn is_well_formed(&self) -> bool {
        self.temperature.is_finite()
            && self.temperature >= 0.0
            && self.top_p.is_finite()
            && (0.0..=1.0).contains(&self.top_p)
            && self.min_p.is_finite()
            && (0.0..=1.0).contains(&self.min_p)
            && self.repeat_penalty.is_finite()
            && self.repeat_penalty > 0.0
            && self.top_k >= 1
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

/// A profile document's fields, exactly as they are written.
///
/// It is private, and that is the whole of how an unchecked profile is kept out of this crate:
/// `serde` can build one of these and nothing else, and the only thing that turns one into a
/// [`ModelProfile`] is [`ProfileTrust::verify`].
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileFields {
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

/// Just enough of a document to name it, so a signature can be checked before the rest is trusted.
#[derive(Debug, Deserialize)]
struct ProfileName {
    profile_id: String,
    profile_revision: ProfileRevision,
}

/// A verified model profile.
#[derive(Clone, Debug, PartialEq)]
pub struct ModelProfile {
    fields: ProfileFields,
}

impl ModelProfile {
    /// Checks a document's fields and wraps them.
    ///
    /// Private, and reached only from [`ProfileTrust::verify`]. Section 22's invariants are checked
    /// here rather than by a caller because a profile that broke one of them is a profile this
    /// product must not run, whoever loaded it.
    fn from_document(document: &[u8]) -> Result<Self> {
        let fields: ProfileFields =
            serde_json::from_slice(document).map_err(|error| DescribeError::ProfileMalformed {
                detail: error.to_string(),
            })?;
        let profile = Self { fields };
        profile.check()?;
        Ok(profile)
    }

    #[allow(clippy::too_many_lines)]
    fn check(&self) -> Result<()> {
        let fields = &self.fields;
        let refuse = |why: &'static str| {
            Err(DescribeError::ProfileRefused {
                profile: fields.profile_id.clone(),
                why,
            })
        };
        if !is_identity(&fields.profile_id) {
            return refuse("an identifier this build will not show");
        }
        for identity in [
            &fields.model.repository,
            &fields.model.revision,
            &fields.conversion.repository,
            &fields.conversion.revision,
            &fields.conversion.quantisation,
            &fields.conversion.format,
            &fields.runtime.binding,
            &fields.runtime.binding_version,
            &fields.runtime.llama_cpp_revision,
            &fields.tokenizer.source_repository,
            &fields.tokenizer.source_revision,
        ] {
            if !is_identity(identity) {
                return refuse("an identity field that is empty or unreasonably long");
            }
        }
        if let Some(converter) = &fields.conversion.converter_revision
            && !is_identity(converter)
        {
            return refuse("a converter revision that is empty or unreasonably long");
        }
        for digest in [
            &fields.tokenizer.tokenizer_sha256,
            &fields.tokenizer.tokenizer_config_sha256,
            &fields.tokenizer.chat_template_sha256,
        ] {
            if !is_sha256_hex(digest) {
                return refuse("a tokenizer digest that is not lowercase SHA-256 hexadecimal");
            }
        }
        if fields.execution.gpu_layers != 0 {
            return refuse("GPU layers, where section 22 fixes zero");
        }
        if fields.components.tools || fields.components.vision {
            return refuse("a tools or vision component, which the profile has none of");
        }
        if !fields.reasoning.is_disabled() {
            return refuse("reasoning, which is off in every profile");
        }
        if !fields.sampler.is_well_formed() {
            return refuse("a sampler value outside the range the runtime accepts");
        }
        if fields.execution.context_tokens == 0
            || fields.execution.max_output_tokens == 0
            || fields.execution.cpu_threads == 0
        {
            return refuse("an execution bound of nought");
        }
        if fields.execution.max_output_tokens >= fields.execution.context_tokens {
            return refuse("an output bound that leaves no room for a prompt");
        }
        if fields.assets.is_empty() {
            return refuse("no assets to verify");
        }
        for asset in &fields.assets {
            if !is_identity(&asset.role)
                || !is_identity(&asset.file_name)
                || !is_identity(&asset.url)
            {
                return refuse("an asset field that is empty or unreasonably long");
            }
            if asset.file_name.contains('/') || asset.file_name.contains('\\') {
                return refuse("an asset file name that is a path rather than a name");
            }
            if !is_sha256_hex(&asset.sha256) {
                return refuse("an asset digest that is not lowercase SHA-256 hexadecimal");
            }
            if asset.bytes == 0 {
                return refuse("an asset of nought bytes");
            }
        }
        if fields
            .assets
            .iter()
            .filter(|asset| asset.role == "weights")
            .count()
            != 1
        {
            return refuse("something other than exactly one weights asset");
        }
        if fields.targets.is_empty() || fields.targets.iter().any(|target| !is_identity(target)) {
            return refuse("no compatible targets, or one that is not a target triple");
        }
        match fields.gate {
            Gate::Default => {
                if !fields.gates.is_empty() {
                    return refuse("the default gate with gates still to pass");
                }
            }
            Gate::Candidate => {
                // All three, in section 22's own words. A candidate that declared fewer would be a
                // candidate an owner could enable by meeting less than the section asks for.
                if !QualificationGate::ALL
                    .iter()
                    .all(|gate| fields.gates.contains(gate))
                {
                    return refuse("the candidate gate without all three declared gates");
                }
            }
        }
        let Some(asset_bytes) = self.checked_asset_bytes() else {
            return refuse("an asset total this host cannot represent");
        };
        if fields.execution.resident_estimate.weights_bytes != asset_bytes {
            return refuse("a weights estimate that is not the size of its own assets");
        }
        if fields.execution.resident_estimate.beyond_the_weights() == 0 {
            return refuse("a resident estimate that is its file size alone");
        }
        Ok(())
    }

    /// Returns the profile's identifier.
    #[must_use]
    pub fn profile_id(&self) -> &str {
        &self.fields.profile_id
    }

    /// Returns the profile's revision.
    #[must_use]
    pub const fn revision(&self) -> ProfileRevision {
        self.fields.profile_revision
    }

    /// Returns whether this is the default profile or a gated candidate.
    #[must_use]
    pub const fn gate(&self) -> Gate {
        self.fields.gate
    }

    /// Returns the gates a candidate declares.
    #[must_use]
    pub fn gates(&self) -> &[QualificationGate] {
        &self.fields.gates
    }

    /// Returns the source model identity.
    #[must_use]
    pub const fn model(&self) -> &ModelIdentity {
        &self.fields.model
    }

    /// Returns the conversion identity.
    #[must_use]
    pub const fn conversion(&self) -> &ConversionIdentity {
        &self.fields.conversion
    }

    /// Returns the runtime identity.
    #[must_use]
    pub const fn runtime(&self) -> &RuntimeIdentity {
        &self.fields.runtime
    }

    /// Returns the assets this profile needs.
    #[must_use]
    pub fn assets(&self) -> &[Asset] {
        &self.fields.assets
    }

    /// Returns the total size of this profile's assets, which is what one download costs.
    #[must_use]
    pub fn asset_bytes(&self) -> u64 {
        // A verified profile always has a representable total: `check` refuses a document whose
        // assets do not add up, and nothing else builds one.
        self.checked_asset_bytes().unwrap_or(u64::MAX)
    }

    fn checked_asset_bytes(&self) -> Option<u64> {
        self.fields
            .assets
            .iter()
            .try_fold(0_u64, |total, asset| total.checked_add(asset.bytes))
    }

    /// Returns the tokenizer identity.
    #[must_use]
    pub const fn tokenizer(&self) -> &TokenizerIdentity {
        &self.fields.tokenizer
    }

    /// Returns the sampler values.
    #[must_use]
    pub const fn sampler(&self) -> &SamplerSettings {
        &self.fields.sampler
    }

    /// Returns the reasoning setting.
    #[must_use]
    pub const fn reasoning(&self) -> &ReasoningSetting {
        &self.fields.reasoning
    }

    /// Returns which optional components the profile has, which is none of them.
    #[must_use]
    pub const fn components(&self) -> &Components {
        &self.fields.components
    }

    /// Returns the execution settings.
    #[must_use]
    pub const fn execution(&self) -> &ExecutionSettings {
        &self.fields.execution
    }

    /// Returns the targets this profile declares as compatible.
    ///
    /// Declared, not proved. [`crate::qualification::Matrix`] is where a target that has actually
    /// been exercised is distinguished from one a profile merely lists.
    #[must_use]
    pub fn targets(&self) -> &[String] {
        &self.fields.targets
    }

    /// Returns whether the profile lists a target.
    #[must_use]
    pub fn supports_target(&self, target: &str) -> bool {
        self.fields.targets.iter().any(|listed| listed == target)
    }
}

/// Returns whether a string is a usable identity: present, bounded and free of control characters.
fn is_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTITY_LEN
        && !value.chars().any(char::is_control)
        && value.trim() == value
}

/// Returns whether a string is exactly a lowercase SHA-256 in hexadecimal.
fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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
    /// different name. Only those two fields are read here, by a decoder that checks nothing else:
    /// the signature has to be checkable *before* the document's contents are trusted.
    ///
    /// # Errors
    ///
    /// Returns [`DescribeError::ProfileMalformed`] when the document does not parse far enough to
    /// name itself.
    pub fn transcript(&self) -> Result<SigningTranscript> {
        let named: ProfileName = serde_json::from_slice(&self.bytes).map_err(|error| {
            DescribeError::ProfileMalformed {
                detail: error.to_string(),
            }
        })?;
        let revision =
            CanonicalValue::integer(i128::from(named.profile_revision.get())).map_err(|error| {
                DescribeError::ProfileMalformed {
                    detail: error.to_string(),
                }
            })?;
        Ok(SigningTranscript::from_elements(
            PROFILE_SIGNING_DOMAIN,
            vec![
                CanonicalValue::Text(named.profile_id),
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
    /// This is the only function anywhere that returns a [`ModelProfile`].
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
        ModelProfile::from_document(signed.document.bytes())
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
    use kr_protocol::scalars::{AuthorisationKey, Signature64};

    use super::{
        DescribeError, Gate, ModelProfile, ProfileDocument, ProfileRevision, ProfileTrust,
        QualificationGate, Result, SignedProfile,
    };

    /// The default profile's document, compiled into this binary.
    pub const DEFAULT_PROFILE_DOCUMENT: &str = include_str!("../profiles/minicpm5-2b-q4-k-m.json");

    /// The gated candidate's document, compiled into this binary.
    pub const CANDIDATE_PROFILE_DOCUMENT: &str = include_str!("../profiles/smollm3-3b-q4-k-m.json");

    /// The default profile's detached signature, unpadded base64url.
    pub const DEFAULT_PROFILE_SIGNATURE: &str =
        include_str!("../profiles/minicpm5-2b-q4-k-m.json.sig");

    /// The gated candidate's detached signature, unpadded base64url.
    pub const CANDIDATE_PROFILE_SIGNATURE: &str =
        include_str!("../profiles/smollm3-3b-q4-k-m.json.sig");

    /// The public half of the key this build's profiles were signed with, unpadded base64url.
    pub const PROFILE_SIGNING_KEY: &str = include_str!("../profiles/signing-key.pub");

    /// Decodes unpadded base64url into a fixed-size array.
    fn decode<const N: usize>(text: &str) -> Option<[u8; N]> {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = Vec::with_capacity(N);
        let mut accumulator = 0_u32;
        let mut bits = 0_u32;
        for byte in text.trim().bytes() {
            let value =
                u32::try_from(ALPHABET.iter().position(|candidate| *candidate == byte)?).ok()?;
            accumulator = (accumulator << 6) | value;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push(u8::try_from((accumulator >> bits) & 0xff).ok()?);
            }
        }
        out.try_into().ok()
    }

    /// Returns the trust set this build ships: exactly the key its own profiles were signed with.
    ///
    /// # Errors
    ///
    /// Returns [`DescribeError::CatalogueRefused`] when this build's own anchor does not decode,
    /// which is a fault in the build rather than in the host.
    pub fn builtin_trust() -> Result<ProfileTrust> {
        let key = decode::<32>(PROFILE_SIGNING_KEY).ok_or(DescribeError::CatalogueRefused {
            why: "this build's profile-signing key does not decode",
        })?;
        Ok(ProfileTrust::new(vec![AuthorisationKey::from_bytes(key)]))
    }

    /// Builds one of this build's shipped profiles as a signed document.
    fn shipped(document: &str, signature: &str) -> Result<SignedProfile> {
        let signature = decode::<64>(signature).ok_or(DescribeError::CatalogueRefused {
            why: "a shipped profile signature does not decode",
        })?;
        let key = decode::<32>(PROFILE_SIGNING_KEY).ok_or(DescribeError::CatalogueRefused {
            why: "this build's profile-signing key does not decode",
        })?;
        Ok(SignedProfile {
            document: ProfileDocument::new(document.as_bytes().to_vec()),
            key: AuthorisationKey::from_bytes(key),
            signature: Signature64::from_bytes(signature),
        })
    }

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
            /// Why each profile was not selected, the default first.
            reasons: Vec<(String, NotSelected)>,
        },
    }

    impl Selection {
        /// Returns the selected profile, when one was selected.
        #[must_use]
        pub fn profile(&self) -> Option<&ModelProfile> {
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

        /// Records every gate as met, which is what a host that has run the whole qualification
        /// says.
        #[must_use]
        pub fn all() -> Self {
            Self(QualificationGate::ALL.to_vec())
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

        /// Returns whether this host may map a profile.
        ///
        /// It is the check the mapping boundary makes, so a caller that obtained a candidate
        /// profile some other way still cannot run it without the gates it declares.
        #[must_use]
        pub fn admits(&self, profile: &ModelProfile) -> bool {
            self.outstanding(profile).is_empty()
        }
    }

    /// The profiles this host can choose between.
    #[derive(Clone, Debug, PartialEq)]
    pub struct Catalogue {
        default: ModelProfile,
        candidates: Vec<ModelProfile>,
    }

    impl Catalogue {
        /// Builds the catalogue this build ships, verifying each profile's signature first.
        ///
        /// # Errors
        ///
        /// Returns a refusal when a shipped profile's signature does not verify or its document is
        /// not one this product will run. Either is a fault in this build rather than in the host.
        pub fn builtin() -> Result<Self> {
            let trust = builtin_trust()?;
            let default = trust.verify(&shipped(
                DEFAULT_PROFILE_DOCUMENT,
                DEFAULT_PROFILE_SIGNATURE,
            )?)?;
            let candidate = trust.verify(&shipped(
                CANDIDATE_PROFILE_DOCUMENT,
                CANDIDATE_PROFILE_SIGNATURE,
            )?)?;
            Self::new(vec![default, candidate])
        }

        /// Builds a catalogue from profiles that have already been verified.
        ///
        /// # Errors
        ///
        /// Returns [`DescribeError::CatalogueRefused`] when the set breaks one of section 22's
        /// rules about the set rather than about a profile: exactly one default, and no repeated
        /// identifier.
        pub fn new(profiles: Vec<ModelProfile>) -> Result<Self> {
            for (index, profile) in profiles.iter().enumerate() {
                if profiles[index + 1..]
                    .iter()
                    .any(|other| other.profile_id() == profile.profile_id())
                {
                    return Err(DescribeError::CatalogueRefused {
                        why: "two profiles with one identifier",
                    });
                }
            }
            let mut defaults: Vec<ModelProfile> = Vec::new();
            let mut candidates: Vec<ModelProfile> = Vec::new();
            for profile in profiles {
                match profile.gate() {
                    Gate::Default => defaults.push(profile),
                    Gate::Candidate => candidates.push(profile),
                }
            }
            let [default] = <[ModelProfile; 1]>::try_from(defaults).map_err(|_| {
                DescribeError::CatalogueRefused {
                    why: "a catalogue names exactly one default profile",
                }
            })?;
            Ok(Self {
                default,
                candidates,
            })
        }

        /// Returns the profiles, the default first.
        #[must_use]
        pub fn profiles(&self) -> Vec<&ModelProfile> {
            std::iter::once(&self.default)
                .chain(self.candidates.iter())
                .collect()
        }

        /// Returns the default profile.
        #[must_use]
        pub const fn default_profile(&self) -> &ModelProfile {
            &self.default
        }

        /// Returns a profile by identifier.
        #[must_use]
        pub fn profile(&self, profile_id: &str) -> Option<&ModelProfile> {
            self.profiles()
                .into_iter()
                .find(|profile| profile.profile_id() == profile_id)
        }

        /// Chooses the profile this host runs.
        ///
        /// The default is considered first, whatever order the catalogue was built from, and it is
        /// chosen when this target is one it lists. A candidate is chosen only when the owner has
        /// recorded every gate it declares, which is what *may be enabled only after meeting the
        /// same declared platform/resource/quality gates* means. When neither answers, the answer
        /// is deterministic metadata.
        ///
        /// Nothing about the host's *condition* reaches this function: there is no memory figure,
        /// no timeout, no previous failure and no output quality in its arguments. That is section
        /// 22's rule that pressure, a timeout or bad output never selects a different model,
        /// expressed as an absence rather than as a branch somebody could add.
        #[must_use]
        pub fn select(&self, target: &str, met: &MetGates) -> Selection {
            let mut reasons = Vec::new();
            for profile in self.profiles() {
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
/// One download per selected profile is what this records, and it records it at the right moment.
/// A fetch is *admitted*, and only a fetch whose assets have been verified is *held*: a download
/// that was cancelled, failed or produced the wrong bytes leaves nothing behind, so the next
/// request fetches again rather than being told the assets are already there.
#[derive(Debug, Default)]
pub struct DownloadLedger {
    admitted: Vec<(String, ProfileRevision)>,
    held: Vec<(String, ProfileRevision)>,
}

impl DownloadLedger {
    /// Builds an empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns whether a profile revision's assets are present and verified.
    #[must_use]
    pub fn holds(&self, profile_id: &str, revision: ProfileRevision) -> bool {
        self.held
            .iter()
            .any(|(id, held)| id == profile_id && *held == revision)
    }

    /// Returns whether a fetch of a profile revision is under way.
    #[must_use]
    pub fn is_running(&self, profile_id: &str, revision: ProfileRevision) -> bool {
        self.admitted
            .iter()
            .any(|(id, admitted)| id == profile_id && *admitted == revision)
    }

    /// Returns how many downloads this environment has completed and verified.
    #[must_use]
    pub fn downloads(&self) -> usize {
        self.held.len()
    }

    /// Records that a fetch's assets were all verified.
    pub fn note_verified(&mut self, profile: &ModelProfile) {
        let key = (profile.profile_id().to_owned(), profile.revision());
        self.admitted.retain(|admitted| admitted != &key);
        if !self.held.contains(&key) {
            self.held.push(key);
        }
    }

    /// Records that a fetch was cancelled or failed. Nothing is held afterwards.
    pub fn note_failed(&mut self, profile: &ModelProfile) {
        let key = (profile.profile_id().to_owned(), profile.revision());
        self.admitted.retain(|admitted| admitted != &key);
        self.held.retain(|held| held != &key);
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
        let key = (asked_for.profile_id().to_owned(), asked_for.revision());
        if self.held.contains(&key) {
            return Ok(Admission::AlreadyHeld);
        }
        if self.admitted.contains(&key) {
            return Ok(Admission::AlreadyRunning);
        }
        self.admitted.push(key);
        Ok(Admission::Download(DownloadPolicy::of(asked_for)))
    }
}

/// What a download request was answered with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Admission {
    /// This environment holds the assets and has verified them; nothing is fetched.
    AlreadyHeld,
    /// A fetch of these assets is already under way; nothing else is started.
    AlreadyRunning,
    /// A fetch is admitted, under exactly this disclosure.
    Download(DownloadPolicy),
}
