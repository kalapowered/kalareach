//! The signed release matrix: which client builds the managed service is meant to work with.
//!
//! The managed service publishes, at [`PATH`], a matrix of tiers: sets of client, relay and
//! discovery versions that work together, the backward-compatible tier first, with the paths that
//! still work when a build is in none of them. The service signs the matrix, and a build pins the
//! key ([`Pins`]): the key the service publishes beside the matrix proves nothing, because whoever
//! served a forged matrix would serve its own key with it.
//!
//! This module reads that matrix and nothing else. [`Document::verify`] accepts a published
//! reply only when every rule of the section below holds, [`HeldMatrix`] keeps the newest accepted
//! copy and decides which copy replaces which, and [`Document::serve`] chooses the tier of one
//! build: the first tier, in the signed order, whose client range holds the build's package
//! version. A build in no tier is told so by a [`RouteError`], which is `UNSUPPORTED_CAPABILITY`
//! with the signed alternatives in this client's own words. [`ReleaseGate`] is what the managed
//! relay lease service asks before it sends a request that takes a new lease; [`check_release`]
//! is the question a release asks before it is published.
//!
//! # What is accepted
//!
//! A reply is accepted when all of these hold, and each is its own [`Refusal`]:
//!
//! 1. its `schemaVersion` is 1, so a newer matrix is one this build does not read;
//! 2. its first tier is the compatible one, its alternatives and tiers are not empty, its window is
//!    positive, and every range is three numbers of one to six digits (as the service reads them:
//!    surrounding white space is ignored and leading zeros are allowed) with the minimum not above
//!    the maximum;
//! 3. its `revision` is a decimal counter of at most 18 digits;
//! 4. its signature verifies under a pinned key over the bytes this module rebuilds, field by
//!    field, in the order the service signs them. The signature covers the schema version, the
//!    revision, the issue date, the window, the alternatives and each tier's identifier,
//!    compatibility and three ranges. It does not cover the prose notes, the `serve` answer or the
//!    published key, and none of those is read as anything but data.
//!
//! A held copy is replaced only by an accepted reply with a higher revision. The same revision with
//! the same signed bytes is a re-read, which refreshes the time and the build that read it; the
//! same revision with other bytes, or a lower revision, is refused and the held copy decides.
//!
//! # What a refusal never does
//!
//! A reply that is not accepted, a reply that is not there, and an older or conflicting revision
//! never make a verdict of their own and never change what the held copy decides. A build with no
//! copy is in the built-in compatible tier: nothing is gated.
//!
//! A copy that another package version read is not acted on as a skew. A matrix that names a
//! release is issued before the release ships, so after an update the held copy usually predates
//! the build; until a read for this build succeeds, a skew from an older build's copy is a copy not
//! yet read for this build ([`View::gates`]).

use std::sync::{Arc, PoisonError, RwLock};

use base64::Engine as _;
use kr_crypto::sign::{SigningTranscript, verify};
use kr_protocol::error::ErrorCode;
use kr_protocol::hello::PackageVersion;
use kr_protocol::scalars::{AuthorisationKey, Signature64};
use kr_protocol::service::GatewayOrigin;
use serde::{Deserialize, Serialize};

use super::ServiceHttp;
use crate::error::ClientError;
use crate::retry::UserAction;
use crate::shown::Shown;

/// Where the managed service publishes the matrix.
pub const PATH: &str = "/api/release-matrix";

/// The most of an answer the transport reads on this path, which `managed_response_limits` sets. A
/// matrix is a few kilobytes.
pub const MAX_ANSWER_BYTES: u64 = 64 * 1024;

/// The domain the service names its signed bytes by, as the one key of the map it signs.
const DOMAIN: &str = "kr-release-matrix/1";

/// The most digits of a revision: a decimal counter that fits a `u64` with room to spare.
const MAX_REVISION_DIGITS: usize = 18;

/// The matrix key the managed service signs with, as unpadded base64url of its 32 bytes.
///
/// A rotation without a release does not exist: a build verifies under these and no others. A
/// rotation is a release with the new key here.
pub const PRODUCTION_PINS: [&str; 1] = ["rXLAn41VOtyCoQ-_rp42_jyBj6eVuv7J9leeBbwMjBI"];

/// The first revision of the managed service's matrix that a build reads.
///
/// Revision 1 listed clients up to 0.4.99 and so no build of this product. A host that holds no
/// copy takes the first verified reply it reads, so a service rolled back to revision 1 would
/// close the lease gate on every such host until a newer revision was published. A revision below
/// this one is refused whether or not a copy is held, and the revision published at a release is
/// never lower than it.
pub const PRODUCTION_FIRST_REVISION: u64 = 2;

/* -------------------------------------------------------------------------- */
/* The pinned keys                                                             */
/* -------------------------------------------------------------------------- */

/// The keys a matrix may be signed by, and the first revision a matrix of that service may have.
#[derive(Clone)]
pub struct Pins {
    keys: Vec<AuthorisationKey>,
    first_revision: u64,
}

crate::debug_as_name!(Pins);

impl Pins {
    /// The keys this build pins, [`PRODUCTION_PINS`], and the first revision it reads,
    /// [`PRODUCTION_FIRST_REVISION`].
    #[must_use]
    pub fn production() -> Self {
        Self {
            keys: PRODUCTION_PINS
                .iter()
                .filter_map(|text| decode_key(text))
                .collect(),
            first_revision: PRODUCTION_FIRST_REVISION,
        }
    }

    /// Keys a test signs with. Any revision is read.
    #[must_use]
    pub const fn of(keys: Vec<AuthorisationKey>) -> Self {
        Self {
            keys,
            first_revision: 1,
        }
    }

    /// The one key a person gives for a service they run, as unpadded base64url of its 32 bytes.
    /// Text that is not such a key gives nothing. The service's matrix may start at revision 1.
    #[must_use]
    pub fn from_key_text(text: &str) -> Option<Self> {
        decode_key(text).map(|key| Self::of(vec![key]))
    }

    /// These pins, refusing a matrix of a revision below `first_revision`.
    #[must_use]
    pub const fn from_revision(mut self, first_revision: u64) -> Self {
        self.first_revision = first_revision;
        self
    }

    /// The first revision a matrix signed under these keys may have.
    #[must_use]
    pub const fn first_revision(&self) -> u64 {
        self.first_revision
    }

    /// Whether the signature verifies over the transcript under one of the keys.
    pub(crate) fn vouches_for(
        &self,
        transcript: &SigningTranscript,
        signature: &Signature64,
    ) -> bool {
        self.keys
            .iter()
            .any(|key| verify(key, transcript, signature).is_ok())
    }
}

/// A key, from unpadded base64url of its 32 bytes.
fn decode_key(text: &str) -> Option<AuthorisationKey> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(text)
        .ok()?;
    Some(AuthorisationKey::from_bytes(bytes.try_into().ok()?))
}

/* -------------------------------------------------------------------------- */
/* Versions                                                                    */
/* -------------------------------------------------------------------------- */

/// Three numbers, compared in order: a version as the matrix writes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Triple(u32, u32, u32);

impl Triple {
    fn of(version: PackageVersion) -> Self {
        Self(
            u32::from(version.major),
            u32::from(version.minor),
            u32::from(version.patch),
        )
    }

    /// Reads a version as the service does: surrounding white space is ignored, then three groups
    /// of one to six ASCII digits, leading zeros allowed.
    fn of_text(text: &str) -> Option<Self> {
        let mut groups = text.trim().split('.');
        let (first, second, third) = (groups.next()?, groups.next()?, groups.next()?);
        if groups.next().is_some() {
            return None;
        }
        Some(Self(group(first)?, group(second)?, group(third)?))
    }
}

fn group(text: &str) -> Option<u32> {
    if text.is_empty() || text.len() > 6 || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse::<u32>().ok()
}

/// A package version from the text a copy was kept with, or nothing.
fn package_version(text: &str) -> Option<PackageVersion> {
    let Triple(major, minor, patch) = Triple::of_text(text)?;
    Some(PackageVersion::new(
        u16::try_from(major).ok()?,
        u16::try_from(minor).ok()?,
        u16::try_from(patch).ok()?,
    ))
}

/* -------------------------------------------------------------------------- */
/* The published reply                                                         */
/* -------------------------------------------------------------------------- */

/// The reply as the service writes it. Members it does not name are data this module never reads:
/// the published key, the `serve` answer and whatever a later service adds.
#[derive(Deserialize)]
struct Published {
    matrix: Wire,
    signature: String,
}

/// Only the schema version, read first so that a later schema is told apart from a damaged reply.
#[derive(Deserialize)]
struct Probe {
    matrix: ProbeMatrix,
}

#[derive(Deserialize)]
struct ProbeMatrix {
    #[serde(rename = "schemaVersion")]
    schema_version: u64,
}

#[derive(Deserialize)]
struct Wire {
    #[serde(rename = "schemaVersion")]
    schema_version: u64,
    revision: String,
    #[serde(rename = "issuedAt")]
    issued_at: String,
    #[serde(rename = "installedClientWindowDays")]
    installed_client_window_days: u64,
    alternatives: Vec<String>,
    tiers: Vec<WireTier>,
}

#[derive(Deserialize)]
struct WireTier {
    id: String,
    compatible: bool,
    client: WireRange,
    relay: WireRange,
    discovery: WireRange,
}

#[derive(Deserialize)]
struct WireRange {
    minimum: String,
    maximum: String,
}

/// The bytes the service signs, field by field, in its order: what is signed is what the service
/// means and not whatever shape the reply had.
#[derive(Serialize)]
struct Signed<'a> {
    schema_version: u64,
    revision: &'a str,
    issued_at: &'a str,
    installed_client_window_days: u64,
    alternatives: &'a [String],
    tiers: Vec<SignedTier<'a>>,
}

#[derive(Serialize)]
struct SignedTier<'a> {
    id: &'a str,
    compatible: bool,
    client: SignedRange<'a>,
    relay: SignedRange<'a>,
    discovery: SignedRange<'a>,
}

#[derive(Serialize)]
struct SignedRange<'a> {
    minimum: &'a str,
    maximum: &'a str,
}

impl<'a> From<&'a WireRange> for SignedRange<'a> {
    fn from(range: &'a WireRange) -> Self {
        Self {
            minimum: &range.minimum,
            maximum: &range.maximum,
        }
    }
}

/* -------------------------------------------------------------------------- */
/* Why a reply was not accepted                                                */
/* -------------------------------------------------------------------------- */

/// Why a reply was not accepted. None of these is a verdict about a build.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The reply is not one document of the shape this build reads.
    Unreadable,
    /// The matrix is of a schema this build does not read.
    NewerSchema,
    /// The matrix breaks a rule of its own: the order of its tiers, an empty list, a window that is
    /// not positive, or a range that is not three numbers or runs backwards.
    Malformed,
    /// The revision is not a decimal counter of at most 18 digits.
    Revision,
    /// The signature does not verify under a pinned key. It may mean a wrong key, or that the
    /// service signs a field this build does not know.
    Signature,
    /// The revision is lower than the one held. A proxy or an edge can serve the previous revision
    /// for a while, so this is not a fault.
    Older,
    /// The revision is the one held, signed over other bytes.
    Conflicts,
    /// The revision is below the first one this build reads for the service
    /// ([`Pins::first_revision`]), whether or not a copy is held. A service rolled back to such a
    /// revision must not decide anything.
    BelowFirst,
}

/* -------------------------------------------------------------------------- */
/* An accepted matrix                                                          */
/* -------------------------------------------------------------------------- */

/// One range of versions, both ends included.
#[derive(Clone, Copy, Debug)]
struct Range {
    low: Triple,
    high: Triple,
}

impl Range {
    fn of_wire(wire: &WireRange) -> Option<Self> {
        let (low, high) = (
            Triple::of_text(&wire.minimum)?,
            Triple::of_text(&wire.maximum)?,
        );
        (low <= high).then_some(Self { low, high })
    }

    fn holds(self, version: Triple) -> bool {
        self.low <= version && version <= self.high
    }
}

/// A tier: the versions that work together. Only the client range decides a build's tier here; the
/// relay and discovery ranges are verified because the signature covers them.
#[derive(Clone, Debug)]
struct Tier {
    compatible: bool,
    client: Range,
}

/// A path that still works when a build is in no tier, as the signature names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Alternative {
    /// The two devices connect directly.
    Direct,
    /// The host and the devices use a relay of the owner's own.
    SelfHostedRelay,
    /// The host and the devices use a discovery server of the owner's own.
    SelfHostedDiscovery,
}

impl Alternative {
    /// The token the matrix signs for it.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::SelfHostedRelay => "self-hosted-relay",
            Self::SelfHostedDiscovery => "self-hosted-discovery",
        }
    }

    /// What a person does, in this client's own words.
    #[must_use]
    pub const fn sentence(self) -> &'static str {
        match self {
            Self::Direct => "connect the devices directly",
            Self::SelfHostedRelay => "run a relay of your own",
            Self::SelfHostedDiscovery => "run a discovery server of your own",
        }
    }

    fn of(token: &str) -> Option<Self> {
        [
            Self::Direct,
            Self::SelfHostedRelay,
            Self::SelfHostedDiscovery,
        ]
        .into_iter()
        .find(|alternative| alternative.token() == token)
    }
}

/// A matrix that passed every rule, with the bytes its signature covered.
#[derive(Clone)]
pub struct Document {
    revision: u64,
    digest: [u8; 32],
    tiers: Vec<Tier>,
    alternatives: Vec<Alternative>,
    unknown_alternatives: usize,
}

crate::debug_fields!(Document { revision });

impl Document {
    /// Accepts a published reply, or says which rule it broke.
    ///
    /// # Errors
    ///
    /// Returns the [`Refusal`] naming the first rule the reply breaks.
    pub fn verify(body: &[u8], pins: &Pins) -> Result<Self, Refusal> {
        let probe = super::json::read::<Probe>(body).map_err(|_| Refusal::Unreadable)?;
        if probe.matrix.schema_version != 1 {
            return Err(Refusal::NewerSchema);
        }
        let published = super::json::read::<Published>(body).map_err(|_| Refusal::Unreadable)?;
        let wire = &published.matrix;

        let tiers = wire
            .tiers
            .iter()
            .map(|tier| {
                // The relay and discovery ranges are checked as well: the signature covers them, and
                // a range that runs backwards is a matrix that breaks its own rule.
                Range::of_wire(&tier.relay)?;
                Range::of_wire(&tier.discovery)?;
                Some(Tier {
                    compatible: tier.compatible,
                    client: Range::of_wire(&tier.client)?,
                })
            })
            .collect::<Option<Vec<_>>>()
            .ok_or(Refusal::Malformed)?;
        let first_is_compatible = wire.tiers.first().is_some_and(|tier| tier.compatible);
        if !first_is_compatible
            || wire.alternatives.is_empty()
            || wire.installed_client_window_days == 0
        {
            return Err(Refusal::Malformed);
        }

        let revision = revision_of(&wire.revision).ok_or(Refusal::Revision)?;

        let transcript = SigningTranscript::keyed(
            DOMAIN,
            &Signed {
                schema_version: wire.schema_version,
                revision: &wire.revision,
                issued_at: &wire.issued_at,
                installed_client_window_days: wire.installed_client_window_days,
                alternatives: &wire.alternatives,
                tiers: wire
                    .tiers
                    .iter()
                    .map(|tier| SignedTier {
                        id: &tier.id,
                        compatible: tier.compatible,
                        client: (&tier.client).into(),
                        relay: (&tier.relay).into(),
                        discovery: (&tier.discovery).into(),
                    })
                    .collect(),
            },
        )
        .map_err(|_| Refusal::Malformed)?;
        let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&published.signature)
            .ok()
            .and_then(|bytes| <[u8; 64]>::try_from(bytes).ok())
            .map(Signature64::from_bytes)
            .ok_or(Refusal::Signature)?;
        if !pins.vouches_for(&transcript, &signature) {
            return Err(Refusal::Signature);
        }
        if revision < pins.first_revision {
            return Err(Refusal::BelowFirst);
        }

        let mut alternatives = Vec::new();
        let mut unknown_alternatives = 0;
        for token in &wire.alternatives {
            match Alternative::of(token) {
                Some(known) if !alternatives.contains(&known) => alternatives.push(known),
                Some(_) => {}
                None => unknown_alternatives += 1,
            }
        }

        Ok(Self {
            revision,
            digest: *transcript.digest().as_bytes(),
            tiers,
            alternatives,
            unknown_alternatives,
        })
    }

    /// The revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// The tier that serves a build: the first one, in the signed order, whose client range holds
    /// its package version.
    #[must_use]
    pub fn serve(&self, build: PackageVersion) -> Verdict {
        let version = Triple::of(build);
        self.tiers
            .iter()
            .find(|tier| tier.client.holds(version))
            .map_or(Verdict::Skew, |tier| Verdict::Served {
                compatible: tier.compatible,
            })
    }

    /// The route error for a build in no tier. `direct` is left out for a host that only uses
    /// relays, as the transport's own alternatives are.
    #[must_use]
    pub fn route_error(&self, relay_only: bool) -> RouteError {
        RouteError {
            revision: self.revision,
            alternatives: self
                .alternatives
                .iter()
                .copied()
                .filter(|alternative| !(relay_only && *alternative == Alternative::Direct))
                .collect(),
            unknown_alternatives: self.unknown_alternatives,
        }
    }
}

fn revision_of(text: &str) -> Option<u64> {
    if text.is_empty()
        || text.len() > MAX_REVISION_DIGITS
        || !text.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    text.parse::<u64>().ok()
}

/// What the matrix says of one build.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// A tier serves the build. `compatible` is false when only a later tier does.
    Served {
        /// Whether the tier is the backward-compatible one.
        compatible: bool,
    },
    /// No tier serves the build.
    Skew,
}

/* -------------------------------------------------------------------------- */
/* The route error                                                             */
/* -------------------------------------------------------------------------- */

/// A build in no tier of the signed matrix, and the paths that still work.
///
/// Nothing the service wrote is in it but what a signature covers, in this client's own words.
#[derive(Clone, PartialEq, Eq)]
pub struct RouteError {
    revision: u64,
    alternatives: Vec<Alternative>,
    unknown_alternatives: usize,
}

crate::debug_fields!(RouteError { revision });

impl RouteError {
    /// The protocol code: a capability this build does not have against this service.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        ErrorCode::UnsupportedCapability
    }

    /// The revision that listed no tier for this build.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// The paths that still work, in the signed order.
    #[must_use]
    pub fn alternatives(&self) -> &[Alternative] {
        &self.alternatives
    }

    /// How many signed alternatives this build does not know and so does not offer.
    #[must_use]
    pub const fn unknown_alternatives(&self) -> usize {
        self.unknown_alternatives
    }

    /// What a person is told.
    #[must_use]
    pub fn said(&self) -> Shown {
        if self.alternatives.is_empty() {
            return crate::shown!(
                "this build is outside every tier of the signed release matrix at revision {}; \
                 update KalaReach on this host to use the managed relay service",
                self.revision
            );
        }
        let paths = Shown::joined(
            self.alternatives
                .iter()
                .map(|alternative| Shown::said(alternative.sentence())),
            ", ",
        );
        crate::shown!(
            "this build is outside every tier of the signed release matrix at revision {}; update \
             KalaReach on this host to use the managed relay service, or {} once set up",
            self.revision,
            paths
        )
    }

    /// The refusal a service client returns: the same one it returns for any service refusal that
    /// asks the person to update, with no delay.
    #[must_use]
    pub fn into_client_error(self) -> ClientError {
        ClientError::Refused {
            error: crate::error::refusal(self.code(), self.said()),
            retry_after_seconds: None,
            action: UserAction::Update,
            service_code: None,
        }
    }
}

/* -------------------------------------------------------------------------- */
/* The held copy                                                               */
/* -------------------------------------------------------------------------- */

/// What a daemon keeps of the newest accepted copy, as it writes it.
///
/// The body is the published text as it was received, verified again at every load, so a file that
/// was edited or signed by a key this build no longer pins is no copy.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Saved {
    /// The origin the copy was read from.
    pub origin: String,
    /// The package version of the build that read it.
    pub read_by: String,
    /// When it was read, in milliseconds since the epoch.
    pub fetched_at_ms: u64,
    /// The published reply.
    pub body: String,
}

crate::debug_fields!(Saved { fetched_at_ms });

/// What happened to the held copy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kept {
    /// A higher revision, or the first copy, replaced what was held.
    Replaced,
    /// The same revision with the same signed bytes: the time and the reading build are new.
    Refreshed,
}

/// An accepted reply, and what to write.
#[derive(Clone)]
pub struct Update {
    /// Whether the copy was replaced or refreshed.
    pub kept: Kept,
    /// The copy as it stands now.
    pub saved: Saved,
}

crate::debug_fields!(Update { kept });

#[derive(Clone)]
struct HeldCopy {
    origin: String,
    read_by: PackageVersion,
    fetched_at_ms: u64,
    body: String,
    document: Document,
}

impl HeldCopy {
    fn saved(&self) -> Saved {
        Saved {
            origin: self.origin.clone(),
            read_by: self.read_by.to_string(),
            fetched_at_ms: self.fetched_at_ms,
            body: self.body.clone(),
        }
    }
}

/// The newest accepted copy of the matrix, shared by whoever reads, evaluates and gates.
#[derive(Clone, Default)]
pub struct HeldMatrix {
    held: Arc<RwLock<Option<HeldCopy>>>,
}

crate::debug_as_name!(HeldMatrix);

/// What the held copy says of one build.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct View {
    /// The held revision.
    pub revision: u64,
    /// When the copy was read, in milliseconds since the epoch.
    pub fetched_at_ms: u64,
    /// What the copy decides for the build.
    pub verdict: Verdict,
    /// Whether this package version read the copy. A skew from a copy another version read is not
    /// acted on.
    pub by_this_build: bool,
}

impl View {
    /// Whether this view closes the gate: a skew that this build's own read found.
    #[must_use]
    pub const fn gates(&self) -> bool {
        matches!(self.verdict, Verdict::Skew) && self.by_this_build
    }
}

impl HeldMatrix {
    /// A host that holds no copy.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, Option<HeldCopy>> {
        self.held.read().unwrap_or_else(PoisonError::into_inner)
    }

    /// Loads what an earlier run kept, verified again against the pins. A copy that does not verify
    /// is no copy.
    ///
    /// # Errors
    ///
    /// Returns the [`Refusal`] that made it no copy. A copy whose reading build is not a package
    /// version is [`Refusal::Unreadable`].
    pub fn restore(&self, pins: &Pins, saved: &Saved) -> Result<(), Refusal> {
        let read_by = package_version(&saved.read_by).ok_or(Refusal::Unreadable)?;
        let document = Document::verify(saved.body.as_bytes(), pins)?;
        *self.held.write().unwrap_or_else(PoisonError::into_inner) = Some(HeldCopy {
            origin: saved.origin.clone(),
            read_by,
            fetched_at_ms: saved.fetched_at_ms,
            body: saved.body.clone(),
            document,
        });
        Ok(())
    }

    /// Takes a reply read from `origin` by the build `build` at `now_ms`.
    ///
    /// A copy kept from another origin counts as none: an operator who changes the origin never has
    /// the old copy decide.
    ///
    /// # Errors
    ///
    /// Returns the [`Refusal`] when the reply is not accepted or is not newer than the held copy;
    /// the held copy is then untouched.
    pub fn accept(
        &self,
        pins: &Pins,
        origin: &str,
        build: PackageVersion,
        now_ms: u64,
        body: &[u8],
    ) -> Result<Update, Refusal> {
        let document = Document::verify(body, pins)?;
        let body = String::from_utf8(body.to_vec()).map_err(|_| Refusal::Unreadable)?;
        let mut held = self.held.write().unwrap_or_else(PoisonError::into_inner);
        let kept = match held.as_ref().filter(|copy| copy.origin == origin) {
            None => Kept::Replaced,
            Some(copy) => match document.revision.cmp(&copy.document.revision) {
                std::cmp::Ordering::Greater => Kept::Replaced,
                std::cmp::Ordering::Equal if document.digest == copy.document.digest => {
                    Kept::Refreshed
                }
                std::cmp::Ordering::Equal => return Err(Refusal::Conflicts),
                std::cmp::Ordering::Less => return Err(Refusal::Older),
            },
        };
        let copy = HeldCopy {
            origin: origin.to_owned(),
            read_by: build,
            fetched_at_ms: now_ms,
            body,
            document,
        };
        let saved = copy.saved();
        *held = Some(copy);
        Ok(Update { kept, saved })
    }

    /// What the held copy says of `build`, when it was read from `origin`.
    #[must_use]
    pub fn view(&self, origin: &str, build: PackageVersion) -> Option<View> {
        let held = self.read();
        let copy = held.as_ref().filter(|copy| copy.origin == origin)?;
        Some(View {
            revision: copy.document.revision,
            fetched_at_ms: copy.fetched_at_ms,
            verdict: copy.document.serve(build),
            by_this_build: copy.read_by == build,
        })
    }

    /// The route error for `build`, when the held copy gates it.
    #[must_use]
    pub fn route_error(
        &self,
        origin: &str,
        build: PackageVersion,
        relay_only: bool,
    ) -> Option<RouteError> {
        let held = self.read();
        let copy = held.as_ref().filter(|copy| copy.origin == origin)?;
        (copy.read_by == build && copy.document.serve(build) == Verdict::Skew)
            .then(|| copy.document.route_error(relay_only))
    }
}

/* -------------------------------------------------------------------------- */
/* The gate                                                                    */
/* -------------------------------------------------------------------------- */

/// What the managed relay lease service asks before it sends a request that takes a new lease.
///
/// It is closed only for a skew that a verified copy of this origin, read by this build, found. A
/// missing, unverified, older or other-build copy leaves it open, so a rotation that outruns a
/// build, a damaged cache or a stale proxy never stops a call.
#[derive(Clone)]
pub struct ReleaseGate {
    held: HeldMatrix,
    origin: GatewayOrigin,
    build: PackageVersion,
    relay_only: bool,
}

crate::debug_fields!(ReleaseGate {
    origin,
    build,
    relay_only
});

impl ReleaseGate {
    /// A gate over the held copy for one origin and one build.
    #[must_use]
    pub const fn new(
        held: HeldMatrix,
        origin: GatewayOrigin,
        build: PackageVersion,
        relay_only: bool,
    ) -> Self {
        Self {
            held,
            origin,
            build,
            relay_only,
        }
    }

    /// The route error, when the gate is closed.
    #[must_use]
    pub fn closed(&self) -> Option<RouteError> {
        self.held
            .route_error(self.origin.as_str(), self.build, self.relay_only)
    }
}

/* -------------------------------------------------------------------------- */
/* Reading it                                                                  */
/* -------------------------------------------------------------------------- */

/// Why the matrix was not read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unread {
    /// The service did not answer, answered with a fault that passes (408, 429, 5xx), or answered
    /// past the bound the transport reads the matrix under.
    Unreachable,
    /// The service answered 501: it publishes no matrix.
    NoMatrix,
    /// The service refused with another status.
    Refused(u16),
}

/// Reads the published reply from `origin`, without declaring a version, so that the service
/// answers the whole signed document and never its unsigned skew answer.
///
/// # Errors
///
/// Returns why the reply was not read.
pub async fn fetch(http: &dyn ServiceHttp, origin: &GatewayOrigin) -> Result<Vec<u8>, Unread> {
    let url = format!("{}{PATH}", origin.as_str());
    let answer = http
        .get_json(&url, &[])
        .await
        .map_err(|_| Unread::Unreachable)?;
    match answer.status {
        200 => Ok(answer.body),
        501 => Err(Unread::NoMatrix),
        408 | 429 | 500..=599 => Err(Unread::Unreachable),
        status => Err(Unread::Refused(status)),
    }
}

/* -------------------------------------------------------------------------- */
/* The release-time question                                                   */
/* -------------------------------------------------------------------------- */

/// A release the published matrix supports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Supported {
    /// The revision that was read.
    pub revision: u64,
    /// Whether the compatible tier serves the release. When only a later tier does, the network
    /// half of the rollout is the operator's to have deployed first.
    pub compatible: bool,
}

/// Why a release is not supported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unsupported {
    /// The published matrix was not read.
    Unread(Unread),
    /// The published reply was not accepted.
    NotVerified(Refusal),
    /// The published matrix lists no tier for the release.
    OutsideEveryTier {
        /// The revision that was read.
        revision: u64,
    },
}

impl Unsupported {
    /// The exit status of the program that asks: 2 for a fault that passes and a retry may mend,
    /// 1 for a refusal.
    #[must_use]
    pub const fn exit_code(self) -> u8 {
        match self {
            Self::Unread(Unread::Unreachable) => 2,
            Self::Unread(_) | Self::NotVerified(_) | Self::OutsideEveryTier { .. } => 1,
        }
    }
}

/// Asks the published matrix at `origin` whether it supports a release of `build`, verifying it
/// under `pins` as a daemon does.
///
/// # Errors
///
/// Returns why the release is not supported.
pub async fn check_release(
    http: &dyn ServiceHttp,
    origin: &GatewayOrigin,
    pins: &Pins,
    build: PackageVersion,
) -> Result<Supported, Unsupported> {
    let body = fetch(http, origin).await.map_err(Unsupported::Unread)?;
    let document = Document::verify(&body, pins).map_err(Unsupported::NotVerified)?;
    match document.serve(build) {
        Verdict::Served { compatible } => Ok(Supported {
            revision: document.revision,
            compatible,
        }),
        Verdict::Skew => Err(Unsupported::OutsideEveryTier {
            revision: document.revision,
        }),
    }
}
