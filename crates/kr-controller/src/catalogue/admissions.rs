//! The admissions a worker is handed: the catalogue's answer turned into records on the wire,
//! each within its bound, and cut into parts that each fit one control frame.
//!
//! Every record has a bound of its own, so the cut never meets a record that cannot fit a frame:
//! an installation whose record would break one (a store path longer than the limit, more builds
//! than an entry may name) is left out of the packages with its reason, and the snapshot goes on
//! without it. A snapshot that needs more than [`MAX_ADMISSION_PARTS`] parts is refused by name.

use std::collections::{BTreeMap, BTreeSet};

use kr_plugin_catalogue::{
    AdmissionPlan, Admissions, Catalogue, CatalogueResult, DisablePolicy, HostPlatform,
    NotAdmittedReason,
};
use kr_plugin_sdk::catalogue::MAX_QUALIFIED_BUILDS;
use kr_plugin_sdk::digest::PayloadDigest;
use kr_protocol::admission::{
    AdmissionRevocation, AdmittedBridge, AdmittedBuild, AdmittedComponent, AdmittedPackage,
    FrameId, LiveRelease, PluginAdmissions, ReleaseOrigin, ReleaseState, RevocationPolicy,
};
use kr_protocol::catalogue::{PluginAdmission, PluginLeftOutReason};
use kr_protocol::envelope::ControlFrame;
use kr_protocol::ids::{EnvironmentId, PluginId, PublisherId};
use kr_protocol::limits::{
    MAX_ADMISSION_PARTS, MAX_ADMISSION_RECORD_BYTES, MAX_ADMITTED_PATH_BYTES, MAX_CONTROL_FRAME_LEN,
};
use kr_protocol::scalars::{Digest256, Nullable, U64};
use kr_worker::broker::connectors::BridgeFacts;

use super::bridge::ReleaseKey;
use super::native_bridge::NativeBridges;

/// What room a part leaves for the frame's own encoding beyond its records.
const PART_SLACK: usize = 1024;

/// One environment's admissions at one revision, as records on the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    /// The admission revision they were computed at.
    pub revision: u64,
    /// The administrator's revocation policy.
    pub policy: RevocationPolicy,
    /// What new bindings may use.
    pub packages: Vec<AdmittedPackage>,
    /// The state of every admitted release and of every release reported live.
    pub releases: Vec<ReleaseState>,
    /// Every installation left out of `packages`, with why: what `plugin.list` says, and, for
    /// every reason but being disabled, what the doctor names.
    pub left_out: Vec<LeftOut>,
}

/// One installation the admissions leave out, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeftOut {
    /// The package.
    pub plugin_id: PluginId,
    /// Why, by kind.
    pub reason: PluginLeftOutReason,
    /// Why, for a person, naming the package and its hash.
    pub detail: String,
}

impl Snapshot {
    /// Returns whether these admissions let new bindings use the installation of `plugin_id` at
    /// `package_digest`, and why not where they do not; `None` for one they do not name.
    #[must_use]
    pub fn admission_of(
        &self,
        plugin_id: &PluginId,
        package_digest: PayloadDigest,
    ) -> Option<PluginAdmission> {
        if self.packages.iter().any(|package| {
            package.plugin_id == *plugin_id && package.package_digest == digest(package_digest)
        }) {
            return Some(PluginAdmission::Admitted);
        }
        self.left_out
            .iter()
            .find(|left| left.plugin_id == *plugin_id)
            .map(|left| PluginAdmission::LeftOut {
                reason: left.reason,
                detail: left.detail.clone(),
            })
    }

    /// Returns every release whose state the snapshot carries.
    #[must_use]
    pub fn covered(&self) -> BTreeSet<ReleaseKey> {
        self.releases
            .iter()
            .map(|state| {
                (
                    state.plugin_id.clone(),
                    state.package_digest,
                    state.origin.clone(),
                )
            })
            .collect()
    }

    /// A snapshot admitting nothing, at `revision`.
    #[must_use]
    pub fn nothing(revision: u64) -> Self {
        Self {
            revision,
            policy: RevocationPolicy::WarnOnly,
            packages: Vec::new(),
            releases: Vec::new(),
            left_out: Vec::new(),
        }
    }

    /// Cuts the snapshot into the parts of one frame, each holding whole records and each within
    /// one control frame, in order.
    ///
    /// # Errors
    ///
    /// Returns why, by name, when the snapshot needs more than [`MAX_ADMISSION_PARTS`] parts.
    pub fn parts(
        &self,
        environment_id: EnvironmentId,
        frame: FrameId,
    ) -> Result<Vec<PluginAdmissions>, String> {
        let empty = PluginAdmissions {
            environment_id,
            frame,
            part: MAX_ADMISSION_PARTS,
            parts: MAX_ADMISSION_PARTS,
            policy: self.policy,
            packages: Vec::new(),
            releases: Vec::new(),
        };
        let budget = MAX_CONTROL_FRAME_LEN
            .saturating_sub(4)
            .saturating_sub(measure(&ControlFrame::PluginAdmissions(Box::new(
                empty.clone(),
            ))))
            .saturating_sub(PART_SLACK);
        let mut parts = vec![empty.clone()];
        let mut used = 0usize;
        let mut add = |cost: usize, place: &mut dyn FnMut(&mut PluginAdmissions)| {
            let last = parts.last_mut().expect("there is always a part");
            let holds = !last.packages.is_empty() || !last.releases.is_empty();
            if holds && used.saturating_add(cost) > budget {
                parts.push(empty.clone());
                used = 0;
            }
            used = used.saturating_add(cost);
            place(parts.last_mut().expect("there is always a part"));
        };
        for package in &self.packages {
            add(measure(package), &mut |part| {
                part.packages.push(package.clone())
            });
        }
        for state in &self.releases {
            add(measure(state), &mut |part| {
                part.releases.push(state.clone())
            });
        }
        let count = u32::try_from(parts.len()).unwrap_or(u32::MAX);
        if count > MAX_ADMISSION_PARTS {
            return Err(format!(
                "the admissions need {count} parts, and a snapshot is at most \
                 {MAX_ADMISSION_PARTS}; the worker keeps the admissions it holds"
            ));
        }
        for (index, part) in parts.iter_mut().enumerate() {
            part.part = u32::try_from(index + 1).unwrap_or(u32::MAX);
            part.parts = count;
        }
        Ok(parts)
    }
}

/// Returns the encoded size of a value, as a frame carries it.
fn measure<T: serde::Serialize + ?Sized>(value: &T) -> usize {
    kr_cbor::to_canonical_vec(value).map_or(usize::MAX, |bytes| bytes.len())
}

/// Computes one environment's admissions on this host, as records on the wire.
///
/// `live` is every release a worker reported; each gets its state. Each admitted package carries
/// the native bridge the host applied for it, where one is applied.
///
/// # Errors
///
/// Returns what the catalogue returned when its records, an index or a package cannot be read.
pub fn snapshot(
    catalogue: &Catalogue,
    bridges: &NativeBridges,
    environment_id: EnvironmentId,
    live: &[LiveRelease],
    host: &HostPlatform,
) -> CatalogueResult<Snapshot> {
    plan(catalogue, bridges, environment_id, live, host)?.complete()
}

/// What a bridge lookup says about one admitted package: the facts of the bridge applied for
/// it, none, or why its journal cannot be read.
type BridgeLookup = Result<Option<BridgeFacts>, String>;

/// What the catalogue's records say, read while the catalogue is held, with the native bridge
/// applied for each package they admit: everything a snapshot needs but the package checks.
#[derive(Clone, Debug)]
pub struct Planned {
    plan: AdmissionPlan,
    bridges: BTreeMap<(PluginId, PayloadDigest), BridgeLookup>,
}

impl Planned {
    /// Returns the admission revision the records were read at.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.plan.revision()
    }

    /// Checks each admitted package's copy, which needs no catalogue, and makes the records.
    ///
    /// # Errors
    ///
    /// Returns what the catalogue returned when a package cannot be read.
    pub fn complete(self) -> CatalogueResult<Snapshot> {
        let admissions = self.plan.complete()?;
        let bridges = self.bridges;
        Ok(wire(&admissions, &|plugin_id, package_digest| {
            bridges
                .get(&(plugin_id.clone(), package_digest))
                .cloned()
                .unwrap_or(Ok(None))
        }))
    }
}

/// Reads what the records say about one environment's admissions on this host, and the native
/// bridge applied for each package they admit, while the caller holds the catalogue.
///
/// # Errors
///
/// Returns what the catalogue returned when a record or an index cannot be read.
pub fn plan(
    catalogue: &Catalogue,
    bridges: &NativeBridges,
    environment_id: EnvironmentId,
    live: &[LiveRelease],
    host: &HostPlatform,
) -> CatalogueResult<Planned> {
    let reported: Vec<kr_plugin_catalogue::LiveRelease> = live
        .iter()
        .filter_map(super::bridge::catalogue_release)
        .collect();
    let plan = catalogue.admission_plan(environment_id, &reported, host)?;
    let facts = plan
        .pending()
        .map(|(plugin_id, package_digest)| {
            (
                (plugin_id.clone(), package_digest),
                bridges
                    .facts(plugin_id, package_digest)
                    .map_err(|error| error.to_string()),
            )
        })
        .collect();
    Ok(Planned {
        plan,
        bridges: facts,
    })
}

/// Returns the state of each release in `live` and of every installed one, which the records
/// alone decide: no package is checked.
///
/// # Errors
///
/// Returns what the catalogue returned when a record or an index cannot be read.
pub fn release_states(
    catalogue: &Catalogue,
    environment_id: EnvironmentId,
    live: &[LiveRelease],
    host: &HostPlatform,
) -> CatalogueResult<Vec<ReleaseState>> {
    let reported: Vec<kr_plugin_catalogue::LiveRelease> = live
        .iter()
        .filter_map(super::bridge::catalogue_release)
        .collect();
    Ok(catalogue
        .admission_plan(environment_id, &reported, host)?
        .releases()
        .iter()
        .map(state)
        .collect())
}

/// Turns the catalogue's admissions into records on the wire, leaving out what breaks a bound.
/// `bridge` says which native bridge is applied for a package.
#[must_use]
pub fn wire(
    admissions: &Admissions,
    bridge: &dyn Fn(&PluginId, PayloadDigest) -> BridgeLookup,
) -> Snapshot {
    let mut left_out: Vec<LeftOut> = admissions
        .not_admitted
        .iter()
        .map(|refused| LeftOut {
            plugin_id: refused.plugin_id.clone(),
            reason: match refused.reason {
                NotAdmittedReason::Disabled => PluginLeftOutReason::Disabled,
                NotAdmittedReason::Revoked(_) => PluginLeftOutReason::Revoked,
                NotAdmittedReason::NotAllowed => PluginLeftOutReason::NotAllowed,
                NotAdmittedReason::Unsupported { .. } => PluginLeftOutReason::Unsupported,
                NotAdmittedReason::Incomplete(_) => PluginLeftOutReason::Incomplete,
                NotAdmittedReason::PastALimit(_) => PluginLeftOutReason::PastALimit,
            },
            detail: refused.detail(),
        })
        .collect();
    let mut packages = Vec::new();
    for package in &admissions.packages {
        match admitted(package, bridge(&package.plugin_id, package.package_digest)) {
            Ok(record) => packages.push(record),
            Err(why) => left_out.push(LeftOut {
                plugin_id: package.plugin_id.clone(),
                reason: PluginLeftOutReason::Unrecordable,
                detail: format!(
                    "{} at {} cannot be handed to a worker: {why}",
                    package.plugin_id, package.package_digest
                ),
            }),
        }
    }
    let releases = admissions.releases.iter().map(state).collect();
    Snapshot {
        revision: admissions.revision,
        policy: policy(admissions.policy),
        packages,
        releases,
        left_out,
    }
}

fn policy(policy: DisablePolicy) -> RevocationPolicy {
    match policy {
        DisablePolicy::WarnOnly => RevocationPolicy::WarnOnly,
        DisablePolicy::DisableAtNextAdmission => RevocationPolicy::DisableAtNextAdmission,
        DisablePolicy::DisableAtOnce => RevocationPolicy::DisableAtOnce,
    }
}

/// The catalogue's own disable policy for the one the configuration names.
pub(super) fn disable_policy_of(policy: RevocationPolicy) -> DisablePolicy {
    match policy {
        RevocationPolicy::WarnOnly => DisablePolicy::WarnOnly,
        RevocationPolicy::DisableAtNextAdmission => DisablePolicy::DisableAtNextAdmission,
        RevocationPolicy::DisableAtOnce => DisablePolicy::DisableAtOnce,
    }
}

/// The wire's word for the catalogue's disable policy.
pub(super) fn revocation_policy_of(policy_in_force: DisablePolicy) -> RevocationPolicy {
    policy(policy_in_force)
}

fn origin(origin: &kr_plugin_catalogue::ReleaseOrigin) -> ReleaseOrigin {
    ReleaseOrigin {
        repository_id: origin.repository_id.to_string(),
        enrolment_key: origin.enrolment_key.as_str().to_owned(),
    }
}

fn digest(digest: kr_plugin_sdk::digest::PayloadDigest) -> Digest256 {
    Digest256::from_bytes(*digest.as_bytes())
}

fn capability_names(
    capabilities: &BTreeSet<kr_plugin_sdk::capability::PluginCapability>,
) -> Vec<String> {
    capabilities
        .iter()
        .map(|capability| capability.as_str().to_owned())
        .collect()
}

/// A path the record names, within its bound.
fn bounded_path(path: &std::path::Path, what: &str) -> Result<String, String> {
    let text = path
        .to_str()
        .ok_or_else(|| format!("its {what} is not text this host can hand over"))?;
    if text.len() > MAX_ADMITTED_PATH_BYTES {
        return Err(format!(
            "its {what} is {} bytes long, and a path handed over is at most \
             {MAX_ADMITTED_PATH_BYTES}",
            text.len()
        ));
    }
    Ok(text.to_owned())
}

/// One admitted package as a record on the wire, or why it cannot be one.
fn admitted(
    package: &kr_plugin_catalogue::AdmittedPackage,
    bridge: BridgeLookup,
) -> Result<AdmittedPackage, String> {
    let publisher_id = PublisherId::new(package.publisher_id.as_str())
        .map_err(|error| format!("its publisher cannot be named here: {error}"))?;
    let package_dir = bounded_path(&package.package_dir, "store path")?;
    if package.builds.len() > MAX_QUALIFIED_BUILDS {
        return Err(format!(
            "its release names {} builds for this host, and an entry names at most \
             {MAX_QUALIFIED_BUILDS}",
            package.builds.len()
        ));
    }
    let bridge = match bridge {
        Ok(Some(facts)) => Some(AdmittedBridge {
            application: facts.application,
            surfaces: facts
                .surfaces
                .iter()
                .map(|surface| surface.as_str().to_owned())
                .collect(),
            forwarder: bounded_path(&facts.forwarder, "native bridge's forwarder")?,
        }),
        Ok(None) => None,
        Err(error) => {
            return Err(format!(
                "the native bridge applied for it cannot be read: {error}"
            ));
        }
    };
    let component = match package.component.as_ref() {
        Some(component) => {
            if component.path.len() > MAX_ADMITTED_PATH_BYTES {
                return Err(format!(
                    "its component's path is {} bytes long, and a path handed over is at most \
                     {MAX_ADMITTED_PATH_BYTES}",
                    component.path.len()
                ));
            }
            Some(AdmittedComponent {
                path: component.path.clone(),
                digest: digest(component.digest),
                bytes: U64::new(component.bytes),
            })
        }
        None => None,
    };
    let record = AdmittedPackage {
        plugin_id: package.plugin_id.clone(),
        publisher_id,
        version: package.version.to_string(),
        package_digest: digest(package.package_digest),
        origin: origin(&package.origin),
        package_dir,
        grants: capability_names(&package.grants),
        bridge: Nullable::from(bridge),
        builds: package
            .builds
            .iter()
            .map(|build| AdmittedBuild {
                executable_digest: digest(build.executable_digest),
                version: build.version.to_string(),
            })
            .collect(),
        component: Nullable::from(component),
    };
    let size = measure(&record);
    if size > MAX_ADMISSION_RECORD_BYTES {
        return Err(format!(
            "its record is {size} bytes, and one record handed over is at most \
             {MAX_ADMISSION_RECORD_BYTES}"
        ));
    }
    Ok(record)
}

fn state(state: &kr_plugin_catalogue::ReleaseState) -> ReleaseState {
    ReleaseState {
        plugin_id: state.plugin_id.clone(),
        package_digest: digest(state.package_digest),
        origin: origin(&state.origin),
        revocation: Nullable::from(state.revocation.as_ref().map(|record| {
            AdmissionRevocation {
                reason: serde_json::to_value(record.reason)
                    .ok()
                    .and_then(|value| value.as_str().map(str::to_owned))
                    .unwrap_or_default(),
                revoked_at: record.revoked_at,
                statement: record.statement.as_str().to_owned(),
            }
        })),
        grant_cap: capability_names(&state.grant_cap),
        ends_at_next_boundary: state.ends_at_next_boundary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::ids::ControllerGeneration;
    use kr_protocol::scalars::Uuid;

    fn frame() -> FrameId {
        FrameId {
            generation: ControllerGeneration::new(1),
            revision: U64::new(7),
            round: U64::new(1),
        }
    }

    /// The largest record a package can be: every build this host may be told of, the longest
    /// paths, and grants and text at their bounds.
    fn largest_package(n: u32) -> AdmittedPackage {
        let long = |prefix: &str| {
            let mut path = format!("/{prefix}/");
            path.push_str(&"p".repeat(MAX_ADMITTED_PATH_BYTES - path.len()));
            path
        };
        AdmittedPackage {
            plugin_id: PluginId::new(format!("kalareach/{}", "n".repeat(60))).expect("an id"),
            publisher_id: PublisherId::new("kalareach").expect("a publisher"),
            version: format!("{n}.0.0-{}", "r".repeat(40)),
            package_digest: Digest256::from_bytes([u8::try_from(n % 256).unwrap_or(0); 32]),
            origin: ReleaseOrigin {
                repository_id: "r".repeat(64),
                enrolment_key: "0123456789abcdef0123456789abcdef".to_owned(),
            },
            package_dir: long("store"),
            grants: kr_plugin_sdk::capability::PluginCapability::ALL
                .iter()
                .map(|capability| capability.as_str().to_owned())
                .collect(),
            bridge: Nullable::some(AdmittedBridge {
                application: "a".repeat(80),
                surfaces: vec!["hook".to_owned(), "channel".to_owned()],
                forwarder: long("forwarder"),
            }),
            builds: (0..MAX_QUALIFIED_BUILDS)
                .map(|build| AdmittedBuild {
                    executable_digest: Digest256::from_bytes(
                        [u8::try_from(build % 256).unwrap_or(0); 32],
                    ),
                    version: format!("{build}.{build}.{build}-{}", "v".repeat(40)),
                })
                .collect(),
            component: Nullable::some(AdmittedComponent {
                path: long("component"),
                digest: Digest256::from_bytes([9; 32]),
                bytes: U64::new(u64::MAX),
            }),
        }
    }

    /// One package at every bound encodes within the record bound and travels in one part; a
    /// snapshot larger than one frame is cut into several, each within a frame, whole records only.
    #[test]
    fn a_record_at_every_bound_fits_and_a_large_snapshot_is_cut_into_whole_records() {
        let largest = largest_package(1);
        assert!(
            measure(&largest) <= MAX_ADMISSION_RECORD_BYTES,
            "{} bytes",
            measure(&largest)
        );
        let one = Snapshot {
            packages: vec![largest],
            ..Snapshot::nothing(7)
        };
        let parts = one
            .parts(EnvironmentId::new(Uuid::NIL), frame())
            .expect("one part");
        assert_eq!(parts.len(), 1);

        let many = Snapshot {
            packages: (0..40).map(largest_package).collect(),
            ..Snapshot::nothing(7)
        };
        let parts = many
            .parts(EnvironmentId::new(Uuid::NIL), frame())
            .expect("several parts");
        assert!(parts.len() > 1, "{}", parts.len());
        let mut carried = 0;
        for (index, part) in parts.iter().enumerate() {
            assert_eq!(part.part as usize, index + 1);
            assert_eq!(part.parts as usize, parts.len());
            assert_eq!(part.frame, frame());
            carried += part.packages.len();
            assert!(
                measure(&ControlFrame::PluginAdmissions(Box::new(part.clone())))
                    <= MAX_CONTROL_FRAME_LEN - 4
            );
        }
        assert_eq!(carried, 40, "every record, whole");
    }

    /// A snapshot past the part bound is refused by name.
    #[test]
    fn a_snapshot_above_the_part_bound_is_refused_by_name() {
        let record = largest_package(1);
        let per_part = (MAX_CONTROL_FRAME_LEN / measure(&record)).max(1);
        let count = u32::try_from(per_part).unwrap_or(u32::MAX) * (MAX_ADMISSION_PARTS + 1);
        let too_many = Snapshot {
            packages: (0..count).map(|_| record.clone()).collect(),
            ..Snapshot::nothing(7)
        };
        let refused = too_many
            .parts(EnvironmentId::new(Uuid::NIL), frame())
            .map(|parts| parts.len());
        assert!(
            matches!(&refused, Err(why) if why.contains("parts")),
            "{refused:?}"
        );
    }

    /// Nothing to hand over is still one part, so the worker is told the revision.
    #[test]
    fn a_snapshot_admitting_nothing_is_one_part() {
        let parts = Snapshot::nothing(7)
            .parts(EnvironmentId::new(Uuid::NIL), frame())
            .expect("one part");
        assert_eq!(parts.len(), 1);
        assert_eq!((parts[0].part, parts[0].parts), (1, 1));
    }
}
