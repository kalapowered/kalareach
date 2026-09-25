//! The cross-boundary checkpoint: what a host, a paired device and the deployed site prove to each
//! other, leg by leg.
//!
//! Every other suite in this repository checks one boundary at a time against something this
//! repository wrote. The legs here cross all of them at once, with the processes a person runs: the
//! `kr-controller` daemon, the `kr-worker` it launches for each session and `kr` on real
//! terminals, all copied from this build to the internal disk; a paired device that is this
//! repository's native client library over iroh; and the deployed site at the origin the run is
//! given.
//!
//! | Leg | What it proves |
//! | --- | --- |
//! | The site | The origin answers and names its build, a host reserves its invitations there, and an origin that serves no rendezvous is a configuration error |
//! | Pairing | A device pairs by short code through the deployed rendezvous and by direct QR over loopback iroh, and each ends in the mutual proof of a paired connection; a wrong code counts against the invitation |
//! | The terminal workflow | A device attached over iroh uses an agent in a managed shell, detaches, reattaches, and is drawn the screen `kr attach` draws; the session ends with its shell |
//! | The catalogue | The host enrols the published catalogue release on the device's owner confirmation, synchronises it and installs the bundled package from it, byte for byte the bundled copy |
//! | The plugin | The installed package is bound into a running session's worker and the device invokes its action through the broker, which refuses the same action without its grant |
//!
//! `scripts/e2e-m1b.sh` runs the legs in that order and reports each.
//!
//! # What a leg starts, and what it leaves
//!
//! A leg makes a directory of its own on the internal disk and puts everything there: the copied
//! binaries, the host's runtime and state directories, the session's working directory, the home
//! every process is given and everything an agent writes. Nothing a leg launches opens this
//! workspace, which may be on a removable volume. Each process a leg starts, or learns the identity
//! of, is recorded by its start identity, and so is every worker the host's registry names and
//! everything beneath it. A process is ended only through what the run holds for it: the handle of
//! a child it started, the start identity it recorded, or the label its daemon gave a launchd job,
//! and never by a name or a pattern. A leg closes what it opened and then checks, in the process
//! table and in the service manager, that nothing it started is still running.
//!
//! On the deployment a leg uses fresh keys, one invitation and one rendezvous room per pairing,
//! and says in its last line what it left there.
//!
//! # When a leg runs
//!
//! [`ORIGIN_VARIABLE`] names the deployment. Without it every leg says why it did nothing and
//! returns, so an ordinary test run of this workspace stays offline. [`REQUIRE_VARIABLE`] set to
//! `1` turns that absence into a failure, which is how the script makes sure a checkpoint it
//! reports on actually ran.
//!
//! # Without the legs
//!
//! The legs and everything they drive are the `legs` feature, on by default. Built without it, the
//! package is [`canonical_origin`] and the `kr-e2e-m1b-origin` program over it, which depend on
//! the protocol crate alone: the scripts that check a deployment ask that program about their
//! origin before they build anything else.

use kr_protocol::pairing::RendezvousOrigin;
use kr_protocol::service::GatewayOrigin;

#[cfg(all(unix, feature = "legs"))]
pub mod agent;
#[cfg(all(unix, feature = "legs"))]
pub mod catalogue;
#[cfg(all(unix, feature = "legs"))]
pub mod ceremony;
#[cfg(all(unix, feature = "legs"))]
pub mod device;
#[cfg(all(unix, feature = "legs"))]
pub mod host;
#[cfg(all(unix, feature = "legs"))]
pub mod room;
#[cfg(all(unix, feature = "legs"))]
pub mod run;
#[cfg(all(unix, feature = "legs"))]
pub mod screen;
#[cfg(all(unix, feature = "legs"))]
pub mod shells;
#[cfg(all(unix, feature = "legs"))]
pub mod site;
#[cfg(all(unix, feature = "legs"))]
pub mod view;
#[cfg(all(unix, feature = "legs"))]
pub mod window;

/// The variable naming the deployed origin the checkpoint runs against.
pub const ORIGIN_VARIABLE: &str = "KR_M1B_ORIGIN";

/// The variable that turns a missing origin into a failure rather than a skip.
pub const REQUIRE_VARIABLE: &str = "KR_REQUIRE_M1B";

/// The variable naming an origin that serves no rendezvous, which the site leg's control uses.
pub const NO_RENDEZVOUS_VARIABLE: &str = "KR_M1B_NO_RENDEZVOUS_ORIGIN";

/// The origin the site leg's control uses when [`NO_RENDEZVOUS_VARIABLE`] names none: the
/// publisher's own web site, which answers HTTPS with a publicly trusted certificate and has no
/// rendezvous routes.
///
/// The control has to be a live HTTPS origin that is not a rendezvous: a host classifies an
/// origin whose TLS or connection fails as a service it could not reach, and only an answer from
/// an origin without the routes as a configuration error.
pub const NO_RENDEZVOUS_ORIGIN: &str = "https://kala.to";

/// The variable naming the published catalogue release the catalogue leg enrols: the HTTPS
/// address its generation is published under, with `metadata/` and `targets/` beneath it as the
/// plugin repository lays a generation out.
pub const RELEASE_VARIABLE: &str = "KR_M1B_CATALOGUE_RELEASE";

/// How long something that has to happen is given before a leg calls it a failure.
///
/// A liveness bound, not a measurement. These legs share machines with builds, and a daemon that
/// takes half a minute to answer is slow rather than broken.
pub const LIVENESS: std::time::Duration = std::time::Duration::from_secs(120);

/// Reads `named` as the origin a checkpoint runs against, by the product's own parsers: a
/// canonical HTTPS rendezvous origin, which is what a host reserves its invitations at, and an
/// origin a service request travels to.
///
/// # Errors
///
/// Returns the rule the value broke, without the value: an address may carry a credential in
/// front of its host.
pub fn canonical_origin(named: &str) -> Result<(RendezvousOrigin, GatewayOrigin), String> {
    let origin = RendezvousOrigin::new(named.to_owned()).map_err(|error| {
        format!("what {ORIGIN_VARIABLE} names is not a canonical HTTPS origin: {error}")
    })?;
    let gateway = GatewayOrigin::new(named.to_owned()).map_err(|error| {
        format!("what {ORIGIN_VARIABLE} names is not an origin a request travels to: {error}")
    })?;
    Ok((origin, gateway))
}

/// The checkpoint one leg runs in: the deployment it was given.
#[derive(Clone, Debug)]
pub struct Checkpoint {
    origin: RendezvousOrigin,
    gateway: GatewayOrigin,
}

impl Checkpoint {
    /// The checkpoint this run was given, or nothing when it was given none.
    ///
    /// # Panics
    ///
    /// Panics when [`REQUIRE_VARIABLE`] says this run was promised a checkpoint and
    /// [`ORIGIN_VARIABLE`] names none, and when what it names is not an HTTPS origin. The value is
    /// never repeated: an address may carry a credential in front of its host.
    #[must_use]
    pub fn from_environment(leg: &str) -> Option<Self> {
        let named = std::env::var(ORIGIN_VARIABLE).unwrap_or_default();
        if named.is_empty() {
            let required = std::env::var(REQUIRE_VARIABLE).is_ok_and(|value| value == "1");
            assert!(
                !required,
                "{REQUIRE_VARIABLE}=1 and {ORIGIN_VARIABLE} names no deployment, so the {leg} leg \
                 could not run"
            );
            eprintln!("skipping the {leg} leg: {ORIGIN_VARIABLE} names no deployment");
            return None;
        }
        let (origin, gateway) = canonical_origin(&named).unwrap_or_else(|rule| panic!("{rule}"));
        Some(Self { origin, gateway })
    }

    /// The deployment, as the rendezvous origin a code invitation reserves at.
    #[must_use]
    pub const fn origin(&self) -> &RendezvousOrigin {
        &self.origin
    }

    /// The deployment, as the origin a service request travels to.
    #[must_use]
    pub const fn gateway(&self) -> &GatewayOrigin {
        &self.gateway
    }

    /// Says what one leg proved, in the words the report uses: the leg, then the deployment.
    pub fn proved(&self, leg: &str, what: &str) {
        println!("{leg}: {what} ({})", self.origin.as_str());
    }

    /// Says what one leg left on the deployment, which the report gathers after the legs.
    pub fn left(&self, leg: &str, what: &str) {
        println!("left on the deployment by the {leg} leg: {what}");
    }
}
