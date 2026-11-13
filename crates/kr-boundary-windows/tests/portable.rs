//! The parts of the boundary that build everywhere, held to real bytes and real files: the policy in
//! its two forms, the two records, the pipe protocol's limits and the doctor's grading.

use std::io::{Cursor, Read};

use kr_boundary_windows::events::{self, BLOCKED};
use kr_boundary_windows::frame::{self, FrameError, Request, Response};
use kr_boundary_windows::manifest::{InstallState, Manifest, ObjectKind, Prior, STORE_VERSION};
use kr_boundary_windows::policy::{
    self, Action, Kind, Mode, Policy, RULE_ALLOW_ALL, RULE_CHECKOUT, RULE_CONNECT,
};
use kr_boundary_windows::state::{Status, Verdict};

const CHECKOUT_SID: &str = "S-1-5-21-111-222-333-1001";
const CONNECT_SID: &str = "S-1-5-21-111-222-333-1002";

fn installed() -> Policy {
    Policy::installed(CHECKOUT_SID, CONNECT_SID)
}

#[test]
fn the_policy_is_read_back_as_it_was_written() {
    let written = installed();
    let read = Policy::parse(&written.render()).expect("the written policy is readable");
    assert_eq!(read, written);
    assert!(read.differences(&written).is_empty());
}

#[test]
fn the_installed_policy_limits_each_account_to_its_own_list() {
    let policy = installed();
    let exe = &policy.collections[policy::EXE];
    assert_eq!(exe.mode, Mode::Enabled);
    assert_eq!(exe.rules.len(), 3);
    let allow = &exe.rules[RULE_ALLOW_ALL];
    assert_eq!(
        (allow.action, allow.sid.as_str()),
        (Action::Allow, "S-1-1-0")
    );
    let checkout = &exe.rules[RULE_CHECKOUT];
    let connect = &exe.rules[RULE_CONNECT];
    assert_eq!(checkout.sid, CHECKOUT_SID);
    assert_eq!(connect.sid, CONNECT_SID);
    assert_eq!(checkout.action, Action::Deny);
    assert_eq!(connect.action, Action::Deny);
    // The connection account runs what the checkout account runs, and more, and only it runs the
    // credential helper.
    assert!(checkout.exceptions.is_subset(&connect.exceptions));
    assert!(connect.exceptions.len() > checkout.exceptions.len());
    let helper = format!(r"{}\{}", policy::BOUNDARY_DIR, policy::HELPER).to_lowercase();
    assert!(connect.exceptions.contains(&helper));
    assert!(!checkout.exceptions.contains(&helper));
    // No shell is on the checkout list: a checkout runs no program but Git.
    assert!(
        checkout
            .exceptions
            .iter()
            .all(|path| path.ends_with(r"\git.exe"))
    );
}

#[test]
fn a_change_to_an_installed_policy_is_named() {
    let mut changed = installed();
    let exe = changed.collections.get_mut(policy::EXE).unwrap();
    exe.rules
        .get_mut(RULE_CONNECT)
        .unwrap()
        .exceptions
        .insert(r"%programfiles%\git\mingw64\libexec\git-core\scalar.exe".to_owned());
    let differences = changed.differences(&installed());
    assert_eq!(differences.len(), 1);
    assert!(differences[0].contains(RULE_CONNECT) && differences[0].contains("exceptions"));

    let mut foreign = installed();
    foreign
        .collections
        .get_mut(policy::EXE)
        .unwrap()
        .rules
        .insert(
            "11111111-1111-1111-1111-111111111111".to_owned(),
            policy::Rule {
                id: "11111111-1111-1111-1111-111111111111".to_owned(),
                kind: Kind::Publisher,
                sid: "S-1-1-0".to_owned(),
                action: Action::Allow,
                conditions: Default::default(),
                exceptions: Default::default(),
            },
        );
    assert_eq!(foreign.foreign_exe_rules().len(), 1);
    let extra = foreign.differences(&installed());
    assert_eq!(extra.len(), 1, "{extra:?}");
    // A rule that the expected policy lacks is named by its identifier. Nothing in the comparison
    // shows who made it, so the line does not say whose it is.
    assert!(
        extra[0].contains("11111111-1111-1111-1111-111111111111")
            && extra[0].contains("which the expected policy does not have"),
        "{extra:?}"
    );
    assert!(!extra[0].contains("ours"), "{extra:?}");

    let mut audit = installed();
    audit.collections.get_mut(policy::EXE).unwrap().mode = Mode::AuditOnly;
    assert!(!audit.differences(&installed()).is_empty());
}

#[test]
fn an_effective_policy_is_read_whatever_its_layout() {
    // Attribute order, braces round the identifier, upper-case paths, comments and collections the
    // installation does not write: the form the platform reports, not the form this crate writes.
    let xml = format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<AppLockerPolicy Version="1">
  <!-- reported by the platform -->
  <RuleCollection EnforcementMode="NotConfigured" Type="Dll" />
  <RuleCollection EnforcementMode="Enabled" Type="Exe">
    <FilePathRule Action="Allow" UserOrGroupSid="s-1-1-0" Id="{{{allow}}}" Name="n" Description="d">
      <Conditions><FilePathCondition Path="*"/></Conditions>
    </FilePathRule>
  </RuleCollection>
</AppLockerPolicy>"#,
        allow = RULE_ALLOW_ALL.to_uppercase()
    );
    let policy = Policy::parse(&xml).expect("readable");
    let exe = &policy.collections["Exe"];
    assert_eq!(exe.mode, Mode::Enabled);
    let rule = &exe.rules[RULE_ALLOW_ALL];
    assert_eq!(rule.sid, "S-1-1-0");
    assert!(rule.conditions.contains("*"));
    assert!(!policy.is_unconfigured());
    assert!(
        Policy::parse("<AppLockerPolicy Version=\"1\" />")
            .unwrap()
            .is_unconfigured()
    );
    assert!(Policy::parse("not a policy").is_err());
    assert!(Policy::parse("<AppLockerPolicy><RuleCollection").is_err());
}

#[test]
fn removal_keeps_the_allow_all_rule_beside_an_administrators_rule() {
    // Alone, the installation's rules all go and the collection is not configured again.
    let (alone, kept) = installed().without_ours();
    assert!(!kept);
    assert!(alone.is_unconfigured());

    // Beside another rule of the executable collection the two deny rules go, and the allow-all
    // rule and the collection's mode stay, so the other rule does not become a block for everyone.
    let mut shared = installed();
    let theirs = "22222222-2222-2222-2222-222222222222".to_owned();
    shared
        .collections
        .get_mut(policy::EXE)
        .unwrap()
        .rules
        .insert(
            theirs.clone(),
            policy::Rule {
                id: theirs.clone(),
                kind: Kind::Path,
                sid: "S-1-5-32-544".to_owned(),
                action: Action::Allow,
                conditions: ["c:\\tools\\*".to_owned()].into(),
                exceptions: Default::default(),
            },
        );
    let (after, kept) = shared.without_ours();
    assert!(kept);
    let exe = &after.collections["Exe"];
    assert_eq!(exe.mode, Mode::Enabled);
    let ids: Vec<&str> = exe.rules.keys().map(String::as_str).collect();
    assert!(ids.contains(&RULE_ALLOW_ALL) && ids.contains(&theirs.as_str()));
    assert!(!ids.contains(&RULE_CHECKOUT) && !ids.contains(&RULE_CONNECT));
}

#[test]
fn the_manifests_replacement_is_a_new_file_under_a_name_nothing_could_have_made() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("manifest.json");
    // What an earlier or another program left under the old fixed name is not touched, not read
    // and not renamed over the manifest.
    let decoy = dir.path().join("manifest.new");
    std::fs::write(&decoy, b"not a manifest").unwrap();
    let mut manifest = Manifest::begin();
    manifest.record(ObjectKind::Service, "KalaReachBoundary", None);
    manifest.save(&path).unwrap();
    manifest.save(&path).unwrap();
    assert_eq!(std::fs::read(&decoy).unwrap(), b"not a manifest");
    assert_eq!(Manifest::load(&path).unwrap(), manifest);
    let names: Vec<String> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        names.len(),
        2,
        "the replacement is gone once it is renamed over the manifest: {names:?}"
    );
}

#[test]
fn the_manifest_is_a_store_that_refuses_what_it_does_not_know() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("manifest.json");
    let mut manifest = Manifest::begin();
    manifest.record(
        ObjectKind::Account,
        "krb-checkout",
        Some("S-1-5-21-1-2-3-1001"),
    );
    manifest.record(ObjectKind::Service, "KalaReachBoundary", None);
    manifest.record(
        ObjectKind::Account,
        "KRB-CHECKOUT",
        Some("S-1-5-21-1-2-3-1009"),
    );
    manifest.persons.push("S-1-5-21-1-2-3-1000".to_owned());
    manifest.save(&path).unwrap();
    let read = Manifest::load(&path).unwrap();
    assert_eq!(read, manifest);
    assert_eq!(
        read.objects.len(),
        2,
        "an object is recorded once, by its name"
    );
    assert_eq!(read.state, InstallState::InProgress);
    assert_eq!(
        read.find(ObjectKind::Account, "krb-checkout")
            .unwrap()
            .detail
            .as_deref(),
        Some("S-1-5-21-1-2-3-1009")
    );

    let unknown_kind = br#"{"store":1,"state":"installed","objects":[{"kind":"wfp-filter","id":"x"}],"persons":[]}"#;
    assert!(
        Manifest::parse(unknown_kind).is_err(),
        "a program that meets an unknown kind refuses"
    );
    let unknown_field = br#"{"store":1,"state":"installed","objects":[],"persons":[],"extra":1}"#;
    assert!(Manifest::parse(unknown_field).is_err());
    let other_version = br#"{"store":2,"state":"installed","objects":[],"persons":[]}"#;
    assert!(Manifest::parse(other_version).is_err());
    assert_eq!(STORE_VERSION, 1);
}

#[test]
fn the_earlier_state_is_written_once_and_never_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("prior.json");
    let first = Prior {
        store: STORE_VERSION,
        appid_start_type: 3,
        appid_running: false,
        policy_xml: "<AppLockerPolicy Version=\"1\" />".to_owned(),
    };
    assert!(first.write_once(&path).unwrap());
    let second = Prior {
        appid_start_type: 2,
        appid_running: true,
        ..first.clone()
    };
    assert!(
        !second.write_once(&path).unwrap(),
        "a repair keeps the first baseline"
    );
    assert_eq!(Prior::load(&path).unwrap(), first);
}

/// A reader that counts the bytes taken from it, so a test can say how much a read consumed.
struct Counting<R> {
    inner: R,
    taken: usize,
}

impl<R: Read> Read for Counting<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let count = self.inner.read(buffer)?;
        self.taken += count;
        Ok(count)
    }
}

#[test]
fn a_frame_is_bounded_before_its_body_is_read() {
    let mut wire = Vec::new();
    frame::write(
        &mut wire,
        &Request::Hello {
            version: frame::VERSION,
        },
    )
    .unwrap();
    frame::write(&mut wire, &Request::Maintenance { on: true }).unwrap();
    let mut reader = Cursor::new(wire);
    assert_eq!(
        frame::read::<_, Request>(&mut reader).unwrap(),
        Request::Hello {
            version: frame::VERSION
        }
    );
    assert_eq!(
        frame::read::<_, Request>(&mut reader).unwrap(),
        Request::Maintenance { on: true }
    );
    assert!(matches!(
        frame::read::<_, Request>(&mut reader),
        Err(FrameError::Closed)
    ));

    // A length over the limit is refused after its four bytes, with the body untouched.
    let mut oversize = u32::try_from(frame::MAX_FRAME + 1)
        .unwrap()
        .to_le_bytes()
        .to_vec();
    oversize.extend(std::iter::repeat_n(b'x', frame::MAX_FRAME + 1));
    let mut counting = Counting {
        inner: Cursor::new(oversize),
        taken: 0,
    };
    assert!(matches!(
        frame::read::<_, Request>(&mut counting),
        Err(FrameError::TooLong(length)) if length == frame::MAX_FRAME + 1
    ));
    assert_eq!(counting.taken, 4);

    // A connection that ends inside a frame is a failure, not a clean end.
    let mut cut = 10_u32.to_le_bytes().to_vec();
    cut.extend_from_slice(b"{\"req");
    assert!(matches!(
        frame::read::<_, Request>(&mut Cursor::new(cut)),
        Err(FrameError::Io(_))
    ));
    let mut half = vec![5_u8, 0];
    assert!(matches!(
        frame::read::<_, Request>(&mut Cursor::new(half.split_off(0))),
        Err(FrameError::Io(_))
    ));

    // A message that is not of this protocol, and one that carries a field it does not name.
    let mut junk = 7_u32.to_le_bytes().to_vec();
    junk.extend_from_slice(b"{\"a\":1}");
    assert!(matches!(
        frame::read::<_, Request>(&mut Cursor::new(junk)),
        Err(FrameError::Malformed(_))
    ));
    let body = br#"{"request":"status","pid":4}"#;
    let mut with_pid = u32::try_from(body.len()).unwrap().to_le_bytes().to_vec();
    with_pid.extend_from_slice(body);
    assert!(
        matches!(
            frame::read::<_, Request>(&mut Cursor::new(with_pid)),
            Err(FrameError::Malformed(_))
        ),
        "a message names no process"
    );

    // A message too long to send is refused before any byte is written.
    let mut sink = Vec::new();
    let huge = Response::Proof {
        ready: false,
        detail: "y".repeat(frame::MAX_FRAME),
    };
    assert!(matches!(
        frame::write(&mut sink, &huge),
        Err(FrameError::TooLong(_))
    ));
    assert!(sink.is_empty());
}

#[test]
fn only_a_proved_absence_is_not_installed() {
    let grade = |verdict: Verdict| verdict.report().status;
    assert_eq!(grade(Verdict::Ready), Status::Ok);
    assert_eq!(grade(Verdict::NotInstalled), Status::Warning);
    for failing in [
        Verdict::Partial("x".into()),
        Verdict::Foreign("x".into()),
        Verdict::Altered("x".into()),
        Verdict::NotInForce("x".into()),
        Verdict::BrokerUnreachable("x".into()),
        Verdict::GitFails("x".into()),
        Verdict::CleanupFailed("x".into()),
        Verdict::Unreadable("x".into()),
    ] {
        assert_eq!(grade(failing), Status::Failed);
    }
    assert!(Verdict::NotInstalled.report().remedy.is_some());
    assert!(Verdict::Ready.report().remedy.is_none());
}

#[test]
fn the_platforms_own_reports_are_read() {
    // What the platform reported on the guest: an effective policy after one was set, the same
    // before any was, a blocked-program event, and a policy-applied event.
    let reported = include_str!("fixtures/effective-policy.xml");
    let policy = Policy::parse(reported).expect("the effective policy is readable");
    let exe = &policy.collections["Exe"];
    assert_eq!(exe.mode, Mode::Enabled);
    assert_eq!(exe.rules.len(), 2);
    let deny = &exe.rules[RULE_CHECKOUT];
    assert_eq!(deny.action, Action::Deny);
    assert_eq!(deny.sid, "S-1-5-21-3148093232-3597522084-1273982340-1006");
    assert!(
        deny.exceptions
            .contains(r"%programfiles%\git\mingw64\bin\git.exe")
    );

    let baseline = Policy::parse(include_str!("fixtures/effective-baseline.xml")).unwrap();
    assert!(baseline.is_unconfigured());
    // Not configured is what removal writes back, so the two forms compare equal.
    let (after, kept) = policy.without_ours();
    assert!(!kept);
    assert!(after.differences(&baseline).is_empty());
    assert_eq!(after, baseline);
    assert_ne!(after, installed());

    let blocked = events::parse(include_str!("fixtures/events-8004.xml")).unwrap();
    assert_eq!(blocked.len(), 1);
    assert_eq!(blocked[0].id, BLOCKED);
    assert_eq!(blocked[0].rule_id, RULE_CHECKOUT);
    assert_eq!(blocked[0].user, deny.sid);
    assert_eq!(blocked[0].path, r"C:\WINDOWS\System32\cmd.exe");

    let applied = events::parse(include_str!("fixtures/events-8001.xml")).unwrap();
    assert_eq!(applied.len(), 1);
    assert_eq!(applied[0].id, 8001);
    assert!(applied[0].rule_id.is_empty());
    assert!(events::parse("<Event>").is_err());
}

#[test]
fn removal_takes_out_only_our_rules_and_leaves_the_rest_as_written() {
    let reported = include_str!("fixtures/effective-policy.xml").trim();
    // Ours only: the collection goes back to not configured.
    let none = policy::strip(reported, &[RULE_ALLOW_ALL, RULE_CHECKOUT, RULE_CONNECT]).unwrap();
    let after = Policy::parse(&none).unwrap();
    assert!(after.is_unconfigured());
    assert!(
        after
            .differences(&Policy::parse(include_str!("fixtures/effective-baseline.xml")).unwrap())
            .is_empty()
    );

    // Beside an administrator's publisher rule, which this crate does not model: the deny rule goes,
    // and the publisher rule survives with its own name and text.
    let theirs = r#"<FilePublisherRule Id="33333333-3333-3333-3333-333333333333" Name="Contoso &amp; sons" Description="d" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePublisherCondition PublisherName="O=CONTOSO" ProductName="*" BinaryName="*"><BinaryVersionRange LowSection="*" HighSection="*" /></FilePublisherCondition></Conditions></FilePublisherRule>"#;
    let shared = reported.replace("</RuleCollection>", &format!("{theirs}</RuleCollection>"));
    let kept = policy::strip(&shared, &[RULE_CHECKOUT, RULE_CONNECT]).unwrap();
    assert!(kept.contains(theirs));
    let parsed = Policy::parse(&kept).unwrap();
    let exe = &parsed.collections["Exe"];
    assert_eq!(exe.mode, Mode::Enabled);
    let ids: Vec<&str> = exe.rules.keys().map(String::as_str).collect();
    assert_eq!(
        ids,
        ["33333333-3333-3333-3333-333333333333", RULE_ALLOW_ALL]
    );
    assert_eq!(
        exe.rules["33333333-3333-3333-3333-333333333333"].kind,
        Kind::Publisher
    );
    assert!(policy::strip("not a policy", &[]).is_err());
}

/// A client asks the platform for what the pipe's list grants and for nothing beyond it. The
/// generic write right of a file carries the append bit, which on a pipe is the right to make
/// another instance of its name, so a request that is made of generic rights is refused for the
/// bit no client is given.
#[test]
fn a_clients_rights_on_the_brokers_pipe_are_the_grant_and_hold_no_right_to_make_an_instance() {
    use kr_boundary_windows::pipe_access::{
        CLIENT, CREATE_INSTANCE, READ_ATTRIBUTES, READ_DATA, SYNCHRONIZE, WRITE_DATA, entry,
    };

    // The least grant: reading and writing the pipe, and the pipe's attributes and the wait that every
    // open asks for; no right over the attributes' change or the permission list. A guest case shows
    // that a list with one bit fewer refuses the open.
    assert_eq!(
        CLIENT,
        READ_DATA | WRITE_DATA | READ_ATTRIBUTES | SYNCHRONIZE
    );
    assert_eq!(CLIENT, 0x0010_0083);
    assert_eq!(
        CLIENT & CREATE_INSTANCE,
        0,
        "no right to make another instance"
    );
    // What a file's generic read and write rights add to the grant: extended attributes and the
    // append bit.
    const FILE_GENERIC_READ: u32 = 0x0012_0089;
    const FILE_GENERIC_WRITE: u32 = 0x0012_0116;
    assert_ne!(
        (FILE_GENERIC_READ | FILE_GENERIC_WRITE) & !CLIENT,
        0,
        "the generic rights ask for more than the grant"
    );
    assert_eq!(CLIENT & !(FILE_GENERIC_READ | FILE_GENERIC_WRITE), 0);
    // The grant a person and the Administrators group receive is this value, written once.
    assert_eq!(entry("BA"), "(A;;0x100083;;;BA)");
    assert_eq!(
        entry("S-1-5-21-111-222-333-1001"),
        "(A;;0x100083;;;S-1-5-21-111-222-333-1001)"
    );
}
