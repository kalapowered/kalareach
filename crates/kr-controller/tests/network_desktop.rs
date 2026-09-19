//! The desktop execution context and the host sleep setting, over the network path.
//!
//! Requirement rows closed here for the paired-device ingress: KR-REQ-03.26 (there is no
//! GUI-control method for a device to call, `automation.manage` is about workflow definitions, and
//! the capability records reach a device with their platform distinctions intact) and KR-REQ-03.27
//! (the setting is off until an owner turns it on, nothing a device can call turns it on, and
//! active inhibition and its reason are in host information over the network). KR-REQ-23.25 in
//! part, for `environment.capabilities` as the fourth of the host-and-environment reads.
//!
//! No worker is started here. Every one of these is a read the daemon answers itself.

mod net_support;

use kr_crypto::keys::DeviceKeys;
use kr_protocol::desktop::{
    DesktopCapabilityReport, EnvironmentCapabilitiesParams, EnvironmentCapabilitiesResult,
    SleepInhibitionSetting, capabilities,
};
use kr_protocol::envelope::ParamsValue;
use kr_protocol::error::ErrorCode;
use kr_protocol::hostinfo::HostInfoResult;
use kr_protocol::ids::EnvironmentId;
use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;
use net_support::Host;

/// A grant that sees a session and nothing more. Capability evidence is not authority, so this is
/// the narrowest grant a device can hold and still reach the host's own reads.
const VIEWER: &[ActionRight] = &[ActionRight::SessionView];

fn typed<T: serde::de::DeserializeOwned + serde::Serialize>(value: &ParamsValue) -> T {
    value.to_typed().expect("a result of the declared shape")
}

/// KR-REQ-03.26: a device receives this host's capability records, with their distinctions.
///
/// The records say what the platform actually offers, name the display server they are about, and
/// say what produced each answer and what makes it stale. A device is given the answer the owner's
/// own socket is given, because capability evidence describes feasibility and never authority:
/// narrowing it would say something untrue about the machine rather than protect anything.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_reads_the_desktop_capability_records_the_owner_reads() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let mut control = host.client().await;
    let (_device, session) = net_support::paired_device(&host, &owner, VIEWER).await;

    let params = EnvironmentCapabilitiesParams {
        environment_id: host.environment_id,
    };
    let locally: EnvironmentCapabilitiesResult = typed(
        &control
            .request(Method::EnvironmentCapabilities, &params)
            .await
            .expect("the call reaches the daemon")
            .expect("environment.capabilities succeeds"),
    );
    let remotely: EnvironmentCapabilitiesResult = session
        .read(Method::EnvironmentCapabilities, &params)
        .await
        .expect("environment.capabilities is served to the device");
    assert!(
        locally
            .desktop
            .records
            .iter()
            .chain(&remotely.desktop.records)
            .all(|record| record.observed_at_ms.get() > 0),
        "every record says when it was observed"
    );
    assert_eq!(
        as_of_one_moment(&locally),
        as_of_one_moment(&remotely),
        "the capability records are the same answer on both ingresses"
    );

    // The answer the device holds carries the display server the records are about. Which server
    // that is depends on the machine this runs on, so what this establishes is that the
    // distinction travels rather than that any particular one was made; the platform reader's own
    // tests are where X11, Wayland and the compositor combinations are told apart.
    assert!(
        !remotely.desktop.records.is_empty(),
        "the host reports one record per capability in the section 11 shape"
    );
    let named = remotely.desktop.desktop.display_server;
    assert_eq!(
        named, locally.desktop.desktop.display_server,
        "and the display server the records are about travels with them"
    );
    for capability in [capabilities::SCREEN_CAPTURE, capabilities::INPUT_INJECTION] {
        let record = remotely
            .desktop
            .record(capability)
            .unwrap_or_else(|| panic!("{capability} has a record of its own"));
        assert_eq!(record.capability.as_str(), capability);
        assert!(
            !record.evidence_source.as_str().is_empty(),
            "{capability} says what produced its answer"
        );
    }
    assert_named_by_capability(&remotely.desktop);

    // Selecting a desktop is not evidence for anything it can do: there is no aggregate record to
    // mistake for a permission, and the registry as a whole has no method that controls a desktop.
    assert!(
        remotely.desktop.record("desktop.automation").is_none(),
        "there is no aggregate desktop-automation capability"
    );
    let controls_a_desktop: Vec<&str> = Method::ALL
        .iter()
        .map(|method| method.as_str())
        .filter(|name| name.starts_with("desktop.") || name.starts_with("gui."))
        .collect();
    assert!(
        controls_a_desktop.is_empty(),
        "this protocol exposes no GUI-control method: {controls_a_desktop:?}"
    );
    // `automation.manage` is the one right whose name could be read as desktop control, and the
    // methods that require it are workflow definitions.
    let under_automation: Vec<&str> = Method::ALL
        .iter()
        .filter(|method| {
            method.entry().required_rights.iter().any(|required| {
                matches!(
                    required.authority,
                    kr_protocol::authority::RequiredAuthority::Right {
                        right: ActionRight::AutomationManage
                    }
                )
            })
        })
        .map(|method| method.as_str())
        .collect();
    assert!(
        under_automation
            .iter()
            .all(|name| name.starts_with("workflow.") || name.starts_with("automation.")),
        "automation.manage covers workflow definitions and nothing else: {under_automation:?}"
    );

    session.close();
    host.stop().await;
}

/// Returns the same answer with every observation time set alike.
///
/// The records are read from the platform when they are asked for, so two answers a moment apart
/// carry two observation times. Everything else about them is what is being compared: a record
/// whose state, evidence, identity, invalidation triggers or disabled reason differed between the
/// two doors would be one door describing a different machine.
fn as_of_one_moment(answer: &EnvironmentCapabilitiesResult) -> EnvironmentCapabilitiesResult {
    let mut levelled = answer.clone();
    for record in &mut levelled.desktop.records {
        record.observed_at_ms = kr_protocol::scalars::TimestampMs::new(0);
    }
    levelled
}

/// Every record names the capability it is about, so no answer stands for another.
fn assert_named_by_capability(report: &DesktopCapabilityReport) {
    let mut seen = std::collections::BTreeSet::new();
    for record in &report.records {
        assert!(
            seen.insert(record.capability.as_str().to_owned()),
            "{} has two records",
            record.capability.as_str()
        );
    }
}

/// KR-REQ-03.26, KR-REQ-23.25: the environment selector still decides which environment is read.
///
/// A capability answer about another environment is not this daemon's to give, whichever door the
/// request arrived at.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_asking_about_another_environment_is_refused_as_the_owner_is() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let mut control = host.client().await;
    let (_device, session) = net_support::paired_device(&host, &owner, VIEWER).await;

    let elsewhere = EnvironmentCapabilitiesParams {
        environment_id: EnvironmentId::new(kr_ipc::new_uuid()),
    };
    let locally = control
        .request(Method::EnvironmentCapabilities, &elsewhere)
        .await
        .expect("the call reaches the daemon")
        .expect_err("this daemon owns one environment");
    let remotely = session
        .read::<_, EnvironmentCapabilitiesResult>(Method::EnvironmentCapabilities, &elsewhere)
        .await
        .expect_err("this daemon owns one environment");
    assert_eq!(locally.code, ErrorCode::InvalidArgument);
    assert_eq!(remotely.code(), ErrorCode::InvalidArgument);
    assert!(
        remotely.to_string().contains(&locally.message),
        "both doors give the same sentence: {} against {remotely}",
        locally.message
    );

    session.close();
    host.stop().await;
}

/// KR-REQ-03.27, in part: a device reads the sleep state, and no method lets it change one.
///
/// Starting a host never enables inhibition, so a host nobody has configured reports the setting
/// off and holds nothing. What a device can do about that is nothing: the registry admits a paired
/// device to no method that writes anything in the host-and-environment group, which is where a
/// power setting would live. What this does not show is the setup assistant's own offer, or the
/// separate choice between mains and battery, neither of which is a protocol method.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_reads_the_sleep_state_and_cannot_turn_inhibition_on() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let mut control = host.client().await;
    let (_device, session) = net_support::paired_device(&host, &owner, VIEWER).await;

    let locally: HostInfoResult = typed(
        &control
            .request(Method::HostInfo, &())
            .await
            .expect("the call reaches the daemon")
            .expect("host.info succeeds"),
    );
    let remotely: HostInfoResult = session
        .read(Method::HostInfo, &())
        .await
        .expect("host.info is served to the device");
    assert_eq!(
        locally.power, remotely.power,
        "the sleep state is the same answer on both ingresses"
    );

    // A host nobody has configured has the setting off, holds no assertion and gives no reason.
    assert_eq!(
        remotely.power.setting,
        SleepInhibitionSetting::Off,
        "starting a host never enables inhibition"
    );
    assert!(!remotely.power.active);
    assert!(
        !remotely.power.reason.is_present(),
        "and a host holding no assertion names no reason for one"
    );
    // The mechanism and the power source are reported whether or not anything is held, because
    // they are what the person needs to find the assertion in the operating system's own listing.
    assert!(
        !remotely.power.mechanism.as_str().is_empty(),
        "the facility that would hold it is named"
    );

    // `environment.capabilities` carries the same state, so a device reading either one is told
    // the same thing about the machine.
    let capabilities: EnvironmentCapabilitiesResult = session
        .read(
            Method::EnvironmentCapabilities,
            &EnvironmentCapabilitiesParams {
                environment_id: host.environment_id,
            },
        )
        .await
        .expect("environment.capabilities is served to the device");
    assert_eq!(capabilities.power, remotely.power);

    // And there is nothing a device can call to change it. Every method the registry admits a
    // paired device to is checked, not a handful of names this test invented: none of them writes
    // anything in the host-and-environment group, which is where a power setting would live.
    let writes_host_configuration: Vec<&str> = Method::ALL
        .iter()
        .filter(|method| {
            let entry = method.entry();
            entry.group == kr_protocol::method::MethodGroup::HostAndEnvironment
                && entry.effect == kr_protocol::authority::EffectClass::Write
                && entry
                    .ingress
                    .contains(&kr_protocol::actor::ActorIngress::PairedDevice)
        })
        .map(|method| method.as_str())
        .collect();
    assert!(
        writes_host_configuration.is_empty(),
        "a device reads this host's state and changes none of it: {writes_host_configuration:?}"
    );

    session.close();
    host.stop().await;
}

/// KR-REQ-03.27, in part: what a device is told about inhibition is what the owner chose.
///
/// Battery use is a separate explicit choice, so the setting is a choice between named values
/// rather than a switch, and the host says why it is holding nothing when the setting is on. What
/// this shows is that a stored choice reaches a device with the reason no assertion is held under
/// it. It does not show an assertion being held: that needs work outstanding, which needs a live
/// session, which needs a worker process this suite does not start.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_inhibition_a_device_reads_is_the_one_the_owner_chose_and_says_why() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let (_device, session) = net_support::paired_device(&host, &owner, VIEWER).await;

    // Until an owner chooses, the host holds nothing and the choice is off.
    let before: HostInfoResult = session
        .read(Method::HostInfo, &())
        .await
        .expect("host.info is served to the device");
    assert_eq!(before.power.setting, SleepInhibitionSetting::Off);

    // The owner chooses mains-only inhibition, which is what setup offers.
    kr_controller::desktop::power::write(
        &host.tree().environment(),
        SleepInhibitionSetting::MainsOnly,
    )
    .expect("the owner's choice is written");

    let after: HostInfoResult = session
        .read(Method::HostInfo, &())
        .await
        .expect("host.info is served to the device");
    assert_eq!(
        after.power.setting,
        SleepInhibitionSetting::MainsOnly,
        "the device is told the choice the owner made"
    );
    assert!(
        !after.power.active,
        "and a host with nothing outstanding still holds nothing"
    );
    assert!(
        !after.power.reason.is_present(),
        "so there is no reason for an assertion to report"
    );
    let withheld = after
        .power
        .withheld_reason
        .0
        .as_deref()
        .expect("a host that holds nothing although the setting is on says why");
    assert!(
        !withheld.is_empty(),
        "and that sentence is one a person can read"
    );
    assert_eq!(
        after.power.sessions_with_work.get(),
        0,
        "nothing is running here, so nothing has verified foreground work"
    );

    session.close();
    host.stop().await;
}
