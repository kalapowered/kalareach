//! The parts of the boundary that build everywhere, held to real bytes and real files: the policy in
//! its two forms, the two records, the pipe protocol's limits and the doctor's grading.

use std::io::{Cursor, Read};

use kr_boundary_windows::events::{self, BLOCKED};
use kr_boundary_windows::frame::{self, FrameError, Request, Response};
use kr_boundary_windows::manifest::{
    InstallState, Manifest, ObjectKind, Outcome, Prior, STORE_VERSION,
};
use kr_boundary_windows::policy::{
    self, Action, Emptied, Kind, Mode, Policy, RULE_ALLOW_ALL, RULE_CHECKOUT, RULE_CONNECT,
    Recorded, Restore, Stays,
};
use kr_boundary_windows::state::{Status, Verdict};

const CHECKOUT_SID: &str = "S-1-5-21-111-222-333-1001";
const CONNECT_SID: &str = "S-1-5-21-111-222-333-1002";

fn installed() -> Policy {
    Policy::installed(CHECKOUT_SID, CONNECT_SID)
}

/// The removal's inspection refuses a data directory that its manifest does not record, so the
/// record that a failed rollback leaves for the administrator's removal holds that entry: a record of
/// a run that failed before its first directory record gains it once, and a record that holds it is
/// left as it is.
#[test]
fn a_record_left_for_the_removal_records_the_data_directory_once() {
    const DATA: &str = r"C:\ProgramData\KalaReach";
    let mut manifest = Manifest::begin();
    assert!(!manifest.records_directory(DATA));
    assert!(manifest.record_directory_where_missing(DATA));
    assert!(manifest.records_directory(DATA));
    assert!(!manifest.record_directory_where_missing(DATA));
    assert_eq!(manifest.of_kind(ObjectKind::Directory).count(), 1);
    let again = Manifest::parse(&manifest.to_bytes().unwrap()).unwrap();
    assert!(again.records_directory(DATA));
    // The entry is an intent with no result, as every directory entry is, and its name matches
    // without regard to the case of ASCII letters, as the inspection reads it.
    assert_eq!(
        again.find(ObjectKind::Directory, DATA).unwrap().outcome,
        None
    );
    assert!(again.records_directory(&DATA.to_ascii_lowercase()));
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
    // The installation's rules are found in a policy that holds them, with or without another
    // rule beside them, and not in one that holds only another rule.
    assert!(installed().holds_our_rules());
    assert!(foreign.holds_our_rules());
    let (alone, _) = installed().without_ours();
    assert!(!alone.holds_our_rules());
    let (shared, kept) = foreign.without_ours();
    assert!(kept && shared.holds_our_rules(), "the allow-all rule stays");
    let mut only_theirs = foreign.clone();
    let exe = only_theirs.collections.get_mut(policy::EXE).unwrap();
    for id in [RULE_ALLOW_ALL, RULE_CHECKOUT, RULE_CONNECT] {
        exe.rules.remove(id);
    }
    assert_eq!(only_theirs.foreign_exe_rules().len(), 1);
    assert!(!only_theirs.holds_our_rules());
    assert!(!Policy::default().holds_our_rules());
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

/// A collection or a rule that lacks a field, or holds a value that the program does not know, is
/// refused as one that the program does not understand, with the field and the value: no default
/// stands in for what the policy did not say.
#[test]
fn a_policy_entry_with_a_missing_or_unknown_field_is_refused_as_not_understood() {
    let rule = |attributes: &str| {
        format!(
            r#"<AppLockerPolicy Version="1"><RuleCollection Type="Exe" EnforcementMode="Enabled"><FilePathRule {attributes} Name="n" Description="d"><Conditions><FilePathCondition Path="*"/></Conditions></FilePathRule></RuleCollection></AppLockerPolicy>"#
        )
    };
    let whole =
        r#"Action="Allow" UserOrGroupSid="S-1-1-0" Id="{b7d3c1e0-5a41-4e7b-9c1d-4b0a6c2f7a01}""#;
    Policy::parse(&rule(whole)).expect("a rule with every field is read");
    let refused = |xml: String, words: &[&str]| {
        let error = Policy::parse(&xml).expect_err("an entry the program does not understand");
        let said = error.to_string();
        assert!(
            said.starts_with("the policy holds an entry that this program does not understand: "),
            "{said}"
        );
        for word in words {
            assert!(said.contains(word), "{said:?} lacks {word:?}");
        }
        assert!(!said.contains("not one that this program reads"), "{said}");
    };
    refused(
        r#"<AppLockerPolicy Version="1"><RuleCollection EnforcementMode="Enabled" /></AppLockerPolicy>"#.to_owned(),
        &["RuleCollection", "no Type"],
    );
    refused(
        r#"<AppLockerPolicy Version="1"><RuleCollection Type="Dll" /></AppLockerPolicy>"#
            .to_owned(),
        &["Dll", "no EnforcementMode"],
    );
    refused(
        r#"<AppLockerPolicy Version="1"><RuleCollection Type="Dll" EnforcementMode="Sometimes" /></AppLockerPolicy>"#.to_owned(),
        &["Dll", "EnforcementMode", "\"Sometimes\"", "does not know"],
    );
    refused(
        rule(r#"UserOrGroupSid="S-1-1-0" Id="{b7d3c1e0-5a41-4e7b-9c1d-4b0a6c2f7a01}""#),
        &["FilePathRule", "no Action"],
    );
    refused(
        rule(
            r#"Action="Maybe" UserOrGroupSid="S-1-1-0" Id="{b7d3c1e0-5a41-4e7b-9c1d-4b0a6c2f7a01}""#,
        ),
        &["FilePathRule", "Action", "\"Maybe\"", "does not know"],
    );
    refused(
        rule(r#"Action="Allow" UserOrGroupSid="S-1-1-0""#),
        &["FilePathRule", "no Id"],
    );
    refused(
        rule(r#"Action="Allow" Id="{b7d3c1e0-5a41-4e7b-9c1d-4b0a6c2f7a01}""#),
        &["FilePathRule", "no UserOrGroupSid"],
    );
    // A field that is there and holds nothing is as unread as one that is missing.
    refused(
        rule(r#"Action="Allow" UserOrGroupSid="S-1-1-0" Id="  ""#),
        &["FilePathRule", "empty Id"],
    );
    refused(
        rule(r#"Action="Allow" UserOrGroupSid="" Id="{b7d3c1e0-5a41-4e7b-9c1d-4b0a6c2f7a01}""#),
        &["FilePathRule", "empty UserOrGroupSid"],
    );
    refused(
        r#"<AppLockerPolicy Version="1"><RuleCollection Type="" EnforcementMode="Enabled" /></AppLockerPolicy>"#.to_owned(),
        &["RuleCollection", "empty Type"],
    );
    // An identifier is checked after it is normalised (braces off, lower case): a rule's is a GUID
    // and an account's is a security identifier, and what is neither is not a value that stands for
    // a rule or an account, so the entry is refused and not taken for one that is not ours.
    for id in [
        "{}",
        "{b7d3c1e0-5a41-4e7b-9c1d-4b0a6c2f7a0}",
        "{b7d3c1e0-5a41-4e7b-9c1d-4b0a6c2f7a0g}",
        "b7d3c1e05a414e7b9c1d4b0a6c2f7a01",
        "b7d3c1e0-5a41",
        "b7d3c1e0-5a41-4e7b-9c1d-4b0a6c2f7a01-1",
        "S-1-5-32-544",
        "theirs",
    ] {
        refused(
            rule(&format!(
                r#"Action="Allow" UserOrGroupSid="S-1-1-0" Id="{id}""#
            )),
            &["FilePathRule", "Id", id, "does not know"],
        );
    }
    for sid in [
        "whatever",
        "S-1",
        "S-1-",
        "S-1-1-0-",
        "S-1-5-",
        "S-2-1-0",
        "S-1-5-21-111-x-333-1001",
        "S-1-+5-32-544",
        "S-1-5-4294967296",
        "S-1-5-021",
        "S-1-281474976710656-1",
        "S-1-0x00000000ffff-1",
        "S-1-0x0001000000000-1",
        "S-1-0x00010000000-1",
        "S-1-0x00010000000g-1",
        "S-1-0x-1",
        "S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15-16",
        "{b7d3c1e0-5a41-4e7b-9c1d-4b0a6c2f7a01}",
    ] {
        refused(
            rule(&format!(
                r#"Action="Allow" UserOrGroupSid="{sid}" Id="{{b7d3c1e0-5a41-4e7b-9c1d-4b0a6c2f7a01}}""#
            )),
            &["FilePathRule", "UserOrGroupSid", sid, "does not know"],
        );
    }
    // What is of the form is read, in either case and with braces or none.
    for attributes in [
        r#"Action="Allow" UserOrGroupSid="S-1-5-21-111-222-333-1001" Id="B7D3C1E0-5A41-4E7B-9C1D-4B0A6C2F7A01""#,
        r#"Action="Deny" UserOrGroupSid=" s-1-5-32-544 " Id=" {b7d3c1e0-5a41-4e7b-9c1d-4b0a6c2f7a01} ""#,
        r#"Action="Deny" UserOrGroupSid="S-1-5-4294967295" Id="b7d3c1e0-5a41-4e7b-9c1d-4b0a6c2f7a01""#,
        r#"Action="Deny" UserOrGroupSid="S-1-281474976710655-0" Id="b7d3c1e0-5a41-4e7b-9c1d-4b0a6c2f7a01""#,
        // An authority of 2^32 or more is written in hexadecimal, twelve digits, in either case.
        r#"Action="Deny" UserOrGroupSid="S-1-0x000100000000-1" Id="b7d3c1e0-5a41-4e7b-9c1d-4b0a6c2f7a01""#,
        r#"Action="Deny" UserOrGroupSid="S-1-0XFFFFFFFFFFFF-5-6" Id="b7d3c1e0-5a41-4e7b-9c1d-4b0a6c2f7a01""#,
        // An identifier with no sub-authority is a structure that the system can write.
        r#"Action="Deny" UserOrGroupSid="S-1-5" Id="b7d3c1e0-5a41-4e7b-9c1d-4b0a6c2f7a01""#,
        r#"Action="Deny" UserOrGroupSid="S-1-1" Id="b7d3c1e0-5a41-4e7b-9c1d-4b0a6c2f7a01""#,
        r#"Action="Deny" UserOrGroupSid="S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15" Id="b7d3c1e0-5a41-4e7b-9c1d-4b0a6c2f7a01""#,
    ] {
        Policy::parse(&rule(attributes)).expect("an identifier of its form is read");
    }
    // The attributes of an entry are read in one pass, and a name that is given twice is refused
    // whichever field is asked for first: the reviewers' example puts the repeated name after a
    // valid one, in an order in which every lookup of a required field stops before it.
    for attributes in [
        r#"Action="Allow" UserOrGroupSid="S-1-1-0" Id="{b7d3c1e0-5a41-4e7b-9c1d-4b0a6c2f7a01}" Id="{}""#,
        r#"Action="Allow" Action="Deny" UserOrGroupSid="S-1-1-0" Id="{b7d3c1e0-5a41-4e7b-9c1d-4b0a6c2f7a01}""#,
        r#"Action="Allow" UserOrGroupSid="S-1-1-0" Id="{b7d3c1e0-5a41-4e7b-9c1d-4b0a6c2f7a01}" x:Id="{}" xmlns:x="urn:x""#,
    ] {
        let error = Policy::parse(&rule(attributes)).expect_err("a repeated attribute is refused");
        assert!(
            matches!(
                error,
                kr_boundary_windows::policy::PolicyError::Unreadable(_)
            ),
            "{error}"
        );
    }
    let condition = |condition: &str| {
        format!(
            r#"<AppLockerPolicy Version="1"><RuleCollection Type="Exe" EnforcementMode="Enabled"><FilePathRule {whole} Name="n" Description="d"><Conditions>{condition}</Conditions></FilePathRule></RuleCollection></AppLockerPolicy>"#
        )
    };
    refused(
        condition("<FilePathCondition/>"),
        &["FilePathCondition", "no Path"],
    );
    refused(
        condition(r#"<FilePathCondition Path=" "/>"#),
        &["FilePathCondition", "empty Path"],
    );
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
fn a_failure_of_the_earlier_state_record_names_that_record_and_not_the_manifest() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("prior.json");
    // A record that is not there cannot be read; one that is not a record is not read.
    let missing = Prior::load(&path).unwrap_err().to_string();
    assert!(
        missing.starts_with("the earlier-state record could not be read:"),
        "{missing}"
    );
    std::fs::write(&path, b"not a record").unwrap();
    let garbage = Prior::load(&path).unwrap_err().to_string();
    assert!(
        garbage.starts_with("the earlier-state record is not one this program reads:"),
        "{garbage}"
    );
    // A record that cannot be written: the folder is not there.
    let record = Prior {
        store: STORE_VERSION,
        appid_start_type: 3,
        appid_running: false,
        policy_xml: String::new(),
    };
    let nowhere = dir.path().join("none").join("prior.json");
    let unwritten = record.write_once(&nowhere).unwrap_err().to_string();
    assert!(
        unwritten.starts_with("the earlier-state record could not be written:"),
        "{unwritten}"
    );
    for text in [&missing, &garbage, &unwritten] {
        assert!(!text.contains("installation record"), "{text}");
    }
    // The manifest keeps its own noun.
    let manifest = Manifest::load(&dir.path().join("manifest.json"))
        .unwrap_err()
        .to_string();
    assert!(
        manifest.starts_with("the installation record could not be read:"),
        "{manifest}"
    );
}

#[test]
fn a_step_records_its_intent_before_it_and_its_result_after_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("manifest.json");
    let mut manifest = Manifest::begin();
    // The intent, written before the step, says nothing of what the step did.
    manifest.record(ObjectKind::Account, "krb-checkout", None);
    manifest.record(ObjectKind::Service, "KalaReachBoundary", None);
    manifest.save(&path).unwrap();
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(
        !text.contains("outcome"),
        "an intent carries no result: {text}"
    );
    let intent = Manifest::load(&path).unwrap();
    assert_eq!(
        intent
            .find(ObjectKind::Account, "krb-checkout")
            .unwrap()
            .outcome,
        None
    );
    // The results come after the steps, each on its own object.
    manifest.conclude(ObjectKind::Account, "krb-checkout", Outcome::Made);
    manifest.conclude(ObjectKind::Service, "KalaReachBoundary", Outcome::Found);
    manifest.save(&path).unwrap();
    let read = Manifest::load(&path).unwrap();
    assert_eq!(read, manifest);
    assert_eq!(
        read.find(ObjectKind::Account, "krb-checkout")
            .unwrap()
            .outcome,
        Some(Outcome::Made)
    );
    assert_eq!(
        read.find(ObjectKind::Service, "KalaReachBoundary")
            .unwrap()
            .outcome,
        Some(Outcome::Found)
    );
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains("\"outcome\": \"made\""), "{text}");
    assert!(text.contains("\"outcome\": \"found\""), "{text}");
    // A later record of the same object changes its detail and keeps its result.
    manifest.record(
        ObjectKind::Account,
        "krb-checkout",
        Some("S-1-5-21-1-2-3-1001"),
    );
    assert_eq!(
        manifest
            .find(ObjectKind::Account, "krb-checkout")
            .unwrap()
            .outcome,
        Some(Outcome::Made)
    );
}

#[test]
fn a_result_of_made_is_never_replaced_by_found_and_a_result_can_stand_alone() {
    let mut manifest = Manifest::begin();
    manifest.record(ObjectKind::Account, "krb-connect", None);
    manifest.conclude(ObjectKind::Account, "krb-connect", Outcome::Made);
    // A repair that finds what an earlier run made leaves it made.
    manifest.conclude(ObjectKind::Account, "KRB-CONNECT", Outcome::Found);
    assert_eq!(
        manifest
            .find(ObjectKind::Account, "krb-connect")
            .unwrap()
            .outcome,
        Some(Outcome::Made)
    );
    // An intent that no result followed takes the result of a later step.
    manifest.record(ObjectKind::Service, "KalaReachBoundary", None);
    manifest.conclude(ObjectKind::Service, "KalaReachBoundary", Outcome::Found);
    assert_eq!(
        manifest
            .find(ObjectKind::Service, "KalaReachBoundary")
            .unwrap()
            .outcome,
        Some(Outcome::Found)
    );
    // The Application Identity service's start is a result with no intent before it.
    assert!(
        manifest
            .find(ObjectKind::AppIdentityStarted, "AppIDSvc")
            .is_none()
    );
    manifest.conclude(ObjectKind::AppIdentityStarted, "AppIDSvc", Outcome::Made);
    assert_eq!(
        manifest
            .find(ObjectKind::AppIdentityStarted, "AppIDSvc")
            .unwrap()
            .outcome,
        Some(Outcome::Made)
    );
}

#[test]
fn a_rollback_acts_on_what_a_run_made_and_the_removal_on_what_a_run_made_or_found() {
    let mut manifest = Manifest::begin();
    manifest.record(ObjectKind::Account, "none", None);
    manifest.record(ObjectKind::Account, "found", None);
    manifest.conclude(ObjectKind::Account, "found", Outcome::Found);
    manifest.record(ObjectKind::Account, "made", None);
    manifest.conclude(ObjectKind::Account, "made", Outcome::Made);
    let acts = |name: &str, rollback: bool| {
        manifest
            .find(ObjectKind::Account, name)
            .unwrap()
            .acted_on_by(rollback)
    };
    // An account whose create failed has an intent and no result: neither undoing step touches it.
    assert!(!acts("none", true));
    assert!(!acts("none", false));
    // An object that the run found was not the run's to take away; the removal takes what a repair
    // found where the manifest listed it.
    assert!(!acts("found", true));
    assert!(acts("found", false));
    assert!(acts("made", true));
    assert!(acts("made", false));
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
fn an_event_number_or_reference_that_is_not_read_is_an_error_and_not_a_default() {
    let event = |inner: &str| format!("<Event><System>{inner}</System></Event>");
    for unread in [
        "<EventID>80x4</EventID>",
        "<EventID></EventID>",
        "<EventRecordID>-1</EventRecordID>",
        "<EventRecordID>12</EventRecordID><EventRecordID>1 2</EventRecordID>",
        "<Data>a&bogus;b</Data>",
        "<Data>a&#xD800;b</Data>",
    ] {
        assert!(events::parse(&event(unread)).is_err(), "{unread}");
    }
    // A reference that splits a number leaves the number whole.
    let read = events::parse(&event(
        "<EventID>&#56;004</EventID><EventRecordID>77</EventRecordID>",
    ))
    .unwrap();
    assert_eq!((read[0].id, read[0].record), (BLOCKED, 77));
}

/// An event is read only with both of its numbers, each given once and holding a number: an empty
/// element, a missing one and a second one of the same name are refused, since a number that the log
/// did not give would stand as zero and a second element would hide the first one's text.
#[test]
fn an_event_with_an_empty_or_missing_number_or_a_second_element_of_one_is_refused() {
    let event = |inner: &str| format!("<Event><System>{inner}</System></Event>");
    let name_of = |inner: &str| match events::parse(&event(inner)) {
        Err(events::EventError::NotANumber { name, .. }) => format!("not a number: {name}"),
        Err(events::EventError::Repeated { name }) => format!("twice: {name}"),
        Err(events::EventError::Missing { name }) => format!("missing: {name}"),
        Err(events::EventError::NotOneText { name }) => format!("beside its text: {name}"),
        other => format!("{other:?}"),
    };
    // An element with no content is a number that is not there, not a record number of zero.
    assert_eq!(
        name_of("<EventID>8004</EventID><EventRecordID/>"),
        "not a number: EventRecordID"
    );
    assert_eq!(
        name_of("<EventID/><EventRecordID>77</EventRecordID>"),
        "not a number: EventID"
    );
    // A number that the event does not carry is not a number of zero either.
    assert_eq!(name_of("<EventID>8004</EventID>"), "missing: EventRecordID");
    assert_eq!(
        name_of("<EventRecordID>77</EventRecordID>"),
        "missing: EventID"
    );
    assert_eq!(name_of(""), "missing: EventID");
    assert!(matches!(
        events::parse("<Event/>"),
        Err(events::EventError::Missing { .. })
    ));
    // A second element of the same name would replace the first one's text before either is read.
    assert_eq!(
        name_of(
            "<EventID>8004</EventID><EventRecordID>bad</EventRecordID><EventRecordID>77</EventRecordID>"
        ),
        "twice: EventRecordID"
    );
    assert_eq!(
        name_of("<EventID>8004</EventID><EventID>8004</EventID><EventRecordID>77</EventRecordID>"),
        "twice: EventID"
    );
    assert_eq!(
        name_of("<EventID>8004</EventID><EventRecordID>77</EventRecordID><EventRecordID/>"),
        "twice: EventRecordID"
    );
    // A number's element holds its text and nothing else: a CDATA section, a comment, a nested
    // element or an instruction beside the text is refused, and so is one before it. The reviewers'
    // own example had a CDATA part after the digits and the parser took the digits for the number.
    assert_eq!(
        name_of("<EventID>8004</EventID><EventRecordID>77<![CDATA[bad]]></EventRecordID>"),
        "beside its text: EventRecordID"
    );
    assert_eq!(
        name_of("<EventID><![CDATA[8004]]></EventID><EventRecordID>77</EventRecordID>"),
        "beside its text: EventID"
    );
    assert_eq!(
        name_of("<EventID>80<!-- one -->04</EventID><EventRecordID>77</EventRecordID>"),
        "beside its text: EventID"
    );
    assert_eq!(
        name_of("<EventID>8004</EventID><EventRecordID>7<Data>x</Data>7</EventRecordID>"),
        "beside its text: EventRecordID"
    );
    assert_eq!(
        name_of("<EventID>8004</EventID><EventRecordID>7<Data/>7</EventRecordID>"),
        "beside its text: EventRecordID"
    );
    assert_eq!(
        name_of("<EventID>8004</EventID><EventRecordID>77<?note x?></EventRecordID>"),
        "beside its text: EventRecordID"
    );
    // A reference that stands for a character is part of the text: it splits the text and nothing
    // else, and a comment or a section in another element of the event is not a number's concern.
    let split = events::parse(&event(
        "<EventID>80&#48;4</EventID><EventRecordID> 77 </EventRecordID><!-- n --><Data><![CDATA[x]]></Data>",
    ))
    .unwrap();
    assert_eq!((split[0].id, split[0].record), (8004, 77));
    // Two events each carry their own numbers once.
    let two = events::parse(&format!(
        "{}{}",
        event("<EventID>8004</EventID><EventRecordID>1</EventRecordID>"),
        event("<EventID>8001</EventID><EventRecordID>2</EventRecordID>")
    ))
    .unwrap();
    assert_eq!(
        two.iter().map(|e| (e.id, e.record)).collect::<Vec<_>>(),
        [(8004, 1), (8001, 2)]
    );
}

#[test]
fn removal_takes_out_only_our_rules_and_leaves_the_rest_as_written() {
    let reported = include_str!("fixtures/effective-policy.xml").trim();
    // Ours only: the collection goes back to not configured.
    let none = policy::strip(
        reported,
        &[RULE_ALLOW_ALL, RULE_CHECKOUT, RULE_CONNECT],
        Emptied::NotConfigured,
    )
    .unwrap();
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
    let kept = policy::strip(
        &shared,
        &[RULE_CHECKOUT, RULE_CONNECT],
        Emptied::NotConfigured,
    )
    .unwrap();
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
    assert!(policy::strip("not a policy", &[], Emptied::NotConfigured).is_err());
}

/// An executable collection that the earlier-state record holds with no rule and a mode (audit
/// only, the state of a computer that audits before it enforces) is written back by the removal as
/// the record holds it, so that the comparison with the record finds no difference. Where the
/// collection is not in the mode the installation set, it is written as it is found, without the
/// installation's rules, and the record's mode is not forced onto it.
#[test]
fn the_removal_writes_an_empty_audit_only_collection_back_as_the_record_holds_it() {
    let record_of = |mode: &str| {
        Policy::parse(&format!(
            r#"<AppLockerPolicy Version="1"><RuleCollection Type="Exe" EnforcementMode="{mode}"></RuleCollection></AppLockerPolicy>"#
        ))
        .unwrap()
    };
    let record = record_of("AuditOnly");
    assert_eq!(record.recorded_empty_mode(), Some(Mode::AuditOnly));
    assert_eq!(record_of("NotConfigured").recorded_empty_mode(), None);
    let installed = Policy::installed("S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1002");
    assert_eq!(installed.exe_mode(), Some(Mode::Enabled));
    assert_eq!(installed.recorded_empty_mode(), None, "it holds rules");
    let xml = installed.render();
    let ours = [RULE_ALLOW_ALL, RULE_CHECKOUT, RULE_CONNECT];

    // Written as the record holds it: no difference. The old write, not configured, is one.
    let back = policy::strip(&xml, &ours, Emptied::Mode(Mode::AuditOnly)).unwrap();
    assert!(back.contains(r#"EnforcementMode="AuditOnly""#), "{back}");
    let after = Policy::parse(&back).unwrap();
    assert!(after.differences(&record).is_empty(), "{back}");
    let flat = policy::strip(&xml, &ours, Emptied::NotConfigured).unwrap();
    assert!(
        !Policy::parse(&flat)
            .unwrap()
            .differences(&record)
            .is_empty()
    );

    // A collection whose mode the installation did not set keeps the mode it has; the rules go.
    let changed = xml.replace(
        r#"EnforcementMode="Enabled""#,
        r#"EnforcementMode="AuditOnly""#,
    );
    let found = policy::strip(&changed, &ours, Emptied::AsFound).unwrap();
    let left = Policy::parse(&found).unwrap();
    assert_eq!(left.exe_mode(), Some(Mode::AuditOnly));
    assert!(left.collections[policy::EXE].rules.is_empty(), "{found}");
    assert!(!found.contains("NotConfigured"), "{found}");
}

/// An earlier-state record that cannot be read selects no write: the removal takes out the
/// installation's rules and leaves the collection as it finds it, whatever its mode, and gives the
/// parse error, so that the lines can say that nothing was written back and nothing compared. It
/// used to write the mode "not configured" for such a record, which the record never gave.
#[test]
fn a_record_whose_policy_does_not_parse_selects_no_write() {
    let unread = Recorded::of(Policy::parse("this is not a policy"));
    let Recorded::Unread(why) = &unread else {
        panic!("a text that is not a policy was read: {unread:?}");
    };
    assert!(why.contains("not one that this program reads"), "{why}");
    let invalid_entry = Recorded::of(Policy::parse(
        r#"<AppLockerPolicy Version="1"><RuleCollection Type="Exe" EnforcementMode="AuditOnly"><FilePathRule Id="x" Name="n" Description="" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="*"/></Conditions></FilePathRule></RuleCollection></AppLockerPolicy>"#,
    ));
    assert!(
        matches!(invalid_entry, Recorded::Unread(_)),
        "{invalid_entry:?}"
    );
    for present in [Mode::Enabled, Mode::AuditOnly, Mode::NotConfigured] {
        for shared in [false, true] {
            assert_eq!(
                policy::restore_for(&unread, present, shared).emptied(),
                Emptied::AsFound,
                "{present:?} {shared}"
            );
        }
    }

    // The collection that the installation set is written without its rules and keeps its mode as
    // found; no mode of a record is written.
    let xml = installed().render();
    let ours = [RULE_ALLOW_ALL, RULE_CHECKOUT, RULE_CONNECT];
    let written = policy::strip(&xml, &ours, Emptied::AsFound).unwrap();
    let left = Policy::parse(&written).unwrap();
    assert_eq!(left.exe_mode(), Some(Mode::Enabled), "{written}");
    assert!(left.collections[policy::EXE].rules.is_empty(), "{written}");
    assert!(!written.contains("NotConfigured"), "{written}");

    // A record that was read keeps its choices: the mode of an empty collection, and not
    // configured where the record gives none.
    let record = |mode: &str| {
        Recorded::of(Policy::parse(&format!(
            r#"<AppLockerPolicy Version="1"><RuleCollection Type="Exe" EnforcementMode="{mode}"></RuleCollection></AppLockerPolicy>"#
        )))
    };
    assert_eq!(record("AuditOnly"), Recorded::Read(Some(Mode::AuditOnly)));
    assert_eq!(record("NotConfigured"), Recorded::Read(None));
    assert_eq!(
        policy::restore_for(&record("AuditOnly"), Mode::Enabled, false),
        Restore::Record(Mode::AuditOnly)
    );
    assert_eq!(
        policy::restore_for(&record("NotConfigured"), Mode::Enabled, false),
        Restore::NotConfigured
    );
    assert_eq!(
        policy::restore_for(&record("AuditOnly"), Mode::Enabled, true),
        Restore::NotConfigured
    );
}

/// The present mode of an executable collection is compared with the mode that the record holds
/// for it, in the three sequences that a computer with an empty audit-only collection can reach.
/// (1) An administrator set the mode back to the record's after the installation: the mode is the
/// record's already, nothing is written back, and the comparison finds no difference, so no line
/// of the removal contradicts another. (2) A removal wrote the record's mode and a later step
/// failed: the retry finds the record's mode there, the same case. (3) An administrator chose
/// another mode after the installation: that mode stays, the comparison allows for it and names
/// it and the record's mode, and the removal can finish. A collection that still has the mode the
/// installation set is a difference in every sequence.
#[test]
fn the_removal_compares_the_present_mode_with_the_records_and_lets_another_mode_stay() {
    let record_xml = r#"<AppLockerPolicy Version="1"><RuleCollection Type="Exe" EnforcementMode="AuditOnly"></RuleCollection></AppLockerPolicy>"#;
    let baseline = Policy::parse(record_xml).unwrap();
    let recorded = Recorded::of(Ok(baseline.clone()));
    let ours = [RULE_ALLOW_ALL, RULE_CHECKOUT, RULE_CONNECT];
    let installed_xml = installed().render();
    let with_mode = |mode: &str| {
        installed_xml.replace(
            r#"EnforcementMode="Enabled""#,
            &format!(r#"EnforcementMode="{mode}""#),
        )
    };
    // What a removal writes for a present policy, and what its check then finds.
    let run = |xml: &str| {
        let present = Policy::parse(xml).unwrap();
        let mode = present.exe_mode().unwrap_or(Mode::NotConfigured);
        let restore = policy::restore_for(&recorded, mode, false);
        let written = policy::strip(xml, &ours, restore.emptied()).unwrap();
        let after = Policy::parse(&written).unwrap();
        let (expected, stays) = policy::expected_after(&baseline, &after);
        (restore, after.differences(&expected), stays)
    };

    // The mode that the installation set: the record's mode is written, and no difference is left.
    let (restore, left, stays) = run(&with_mode("Enabled"));
    assert_eq!(restore, Restore::Record(Mode::AuditOnly));
    assert!(left.is_empty() && stays.is_none(), "{left:?}");

    // (1) The record's mode is there already, with the installation's rules still in the
    // collection: it is written as found, and nothing is said to differ.
    let (restore, left, stays) = run(&with_mode("AuditOnly"));
    assert_eq!(restore, Restore::Same(Mode::AuditOnly));
    assert!(left.is_empty() && stays.is_none(), "{left:?}");

    // (2) The retry after a removal that wrote the record's mode and stopped later: no rule is
    // left, the mode is the record's.
    let (restore, left, stays) = run(record_xml);
    assert_eq!(restore, Restore::Same(Mode::AuditOnly));
    assert!(left.is_empty() && stays.is_none(), "{left:?}");

    // (3) Another mode than the installation's and the record's stays, and the check finishes with
    // the two modes named.
    let (restore, left, stays) = run(&with_mode("NotConfigured"));
    assert_eq!(
        restore,
        Restore::Stays {
            present: Mode::NotConfigured,
            recorded: Mode::AuditOnly
        }
    );
    assert!(left.is_empty(), "{left:?}");
    assert_eq!(
        stays,
        Some(Stays {
            present: Mode::NotConfigured,
            recorded: Mode::AuditOnly
        })
    );
    // The repeated removal of (3) finds the same, and finishes the same way.
    let (_, left, stays) = run(
        r#"<AppLockerPolicy Version="1"><RuleCollection Type="Exe" EnforcementMode="NotConfigured"></RuleCollection></AppLockerPolicy>"#,
    );
    assert!(left.is_empty() && stays.is_some(), "{left:?}");

    // A collection that is empty after the write and still has the installation's mode (a domain
    // policy can keep it so) is a difference, not a mode that stays: the removal does not finish on
    // it, and no mode is named as one that stays.
    let enabled = Policy::parse(
        r#"<AppLockerPolicy Version="1"><RuleCollection Type="Exe" EnforcementMode="Enabled"></RuleCollection></AppLockerPolicy>"#,
    )
    .unwrap();
    let (expected, stays) = policy::expected_after(&baseline, &enabled);
    assert!(stays.is_none(), "{stays:?}");
    assert!(
        !enabled.differences(&expected).is_empty(),
        "an empty collection that has the installation's mode is a difference"
    );

    // What each way of leaving the collection writes: the record's mode, nothing (as found) where the
    // mode is already the record's, where another stays and where the record was not read, and not
    // configured otherwise.
    assert_eq!(
        Restore::Record(Mode::AuditOnly).emptied(),
        Emptied::Mode(Mode::AuditOnly)
    );
    for left in [
        Restore::Same(Mode::AuditOnly),
        Restore::Stays {
            present: Mode::AuditOnly,
            recorded: Mode::Enabled,
        },
        Restore::Unread("why".to_owned()),
    ] {
        assert_eq!(left.emptied(), Emptied::AsFound, "{left:?}");
    }
    assert_eq!(Restore::NotConfigured.emptied(), Emptied::NotConfigured);
    // A record that holds an enabled empty collection and a collection that was set to audit only
    // after the installation: audit only stays.
    let enabled_record = Recorded::of(Policy::parse(
        r#"<AppLockerPolicy Version="1"><RuleCollection Type="Exe" EnforcementMode="Enabled"></RuleCollection></AppLockerPolicy>"#,
    ));
    assert_eq!(
        policy::restore_for(&enabled_record, Mode::AuditOnly, false),
        Restore::Stays {
            present: Mode::AuditOnly,
            recorded: Mode::Enabled
        }
    );
    // A collection that still holds the installation's rules is no collection that stays: the rules
    // are a difference whatever the mode.
    let with_rules = Policy::parse(&with_mode("NotConfigured")).unwrap();
    let (_, stays) = policy::expected_after(&baseline, &with_rules);
    assert!(stays.is_none());
    // The mode that the installation set, left in place after the removal, is a difference that
    // keeps the removal from finishing: no allowance is made for it.
    let still_enforced = Policy::parse(&with_mode("Enabled")).unwrap();
    let (expected, stays) = policy::expected_after(&baseline, &still_enforced);
    assert!(stays.is_none());
    assert!(!still_enforced.differences(&expected).is_empty());
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

#[test]
fn the_folder_above_the_program_directory_is_held_with_its_identity_and_its_result() {
    let folder = "C:\\Program Files\\KalaReach";
    let identity = "0000000000000001:00000000000000000000000000000002";
    let mut manifest = Manifest::begin();
    // The intent comes first, with no identity and no result.
    manifest.record(ObjectKind::ProgramFolder, folder, None);
    let object = manifest.find(ObjectKind::ProgramFolder, folder).unwrap();
    assert_eq!((object.outcome, object.detail.as_deref()), (None, None));
    // The call that made the folder gives its identity, and then the result.
    manifest.record(ObjectKind::ProgramFolder, folder, Some(identity));
    manifest.conclude(ObjectKind::ProgramFolder, folder, Outcome::Made);
    // A repair finds the folder and records the intent again with the identity that it holds; the
    // result `found` never replaces `made`.
    manifest.record(ObjectKind::ProgramFolder, folder, Some(identity));
    manifest.conclude(ObjectKind::ProgramFolder, folder, Outcome::Found);
    let reread = Manifest::parse(&manifest.to_bytes().unwrap()).unwrap();
    let object = reread.find(ObjectKind::ProgramFolder, folder).unwrap();
    assert_eq!(object.outcome, Some(Outcome::Made));
    assert_eq!(object.detail.as_deref(), Some(identity));
    // A folder that stood there before the run has the result `found`, and a rollback does not act
    // on it; the removal's own rule for this kind is the folder's record, not `acted_on_by`.
    let mut manifest = Manifest::begin();
    manifest.record(ObjectKind::ProgramFolder, folder, None);
    manifest.conclude(ObjectKind::ProgramFolder, folder, Outcome::Found);
    let object = manifest.find(ObjectKind::ProgramFolder, folder).unwrap();
    assert!(!object.acted_on_by(true));
}
