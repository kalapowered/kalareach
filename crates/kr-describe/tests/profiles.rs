//! Section 22's floor and its profiles: a title on every host, where a model may be mapped, and
//! what a signed profile has to say before anything is loaded.
//!
//! Nothing here needs a runtime, a queue or a store. That is the point of the section these tests
//! cover: a host with no model at all still names and orders every session, and a profile is a
//! statement that can be checked before a byte of it is fetched.

mod support;

use kr_describe::budget::{Budgets, GIB, ResidentCost};
use kr_describe::environment::{
    DataAccessChoice, EnvironmentKind, ExecutionEnvironment, MachineGroup, ModelMapping, Placement,
    PlacementRefusal,
};
use kr_describe::error::DescribeError;
use kr_describe::metadata::{
    LabelSource, LifecycleFacts, RepositoryFacts, SessionFacts, SessionLabel, VerifiedStatus,
    deterministic_title,
};
use kr_describe::profile::catalogue::{Catalogue, MetGates, NotSelected, Selection};
use kr_describe::profile::{
    Admission, DownloadLedger, DownloadPolicy, Gate, ModelProfile, ProfileDocument, ProfileTrust,
    QualificationGate, SignedProfile, catalogue,
};
use kr_protocol::scalars::TimestampMs;

use support::{MAC, built_in, default_profile, environment_id, native};

/// KR-REQ-22.02: a title and a status are available with no model, no network and no store.
#[test]
fn every_host_has_a_title_and_a_status_with_no_model_at_all() {
    let facts = SessionFacts {
        repository: Some(RepositoryFacts {
            name: "kalareach".to_owned(),
            branch: Some("main".to_owned()),
        }),
        ..SessionFacts::default()
    };
    let status = VerifiedStatus::of(&LifecycleFacts {
        started: true,
        reachable: true,
        ..LifecycleFacts::default()
    });
    let label = SessionLabel::from_metadata(&facts, status);
    assert_eq!(label.title.as_str(), "kalareach (main)");
    assert_eq!(label.source, LabelSource::Metadata);
    assert_eq!(label.status, VerifiedStatus::Running);
    assert!(label.activity.is_none());
}

/// KR-REQ-22.02: the same facts give the same title, whatever order they arrive in.
#[test]
fn a_title_is_deterministic_and_falls_back_through_the_facts_it_has() {
    let repository = SessionFacts {
        repository: Some(RepositoryFacts {
            name: "kalareach".to_owned(),
            branch: None,
        }),
        directory: Some("crates".to_owned()),
        ..SessionFacts::default()
    };
    assert_eq!(deterministic_title(&repository).as_str(), "kalareach");
    assert_eq!(
        deterministic_title(&repository),
        deterministic_title(&repository)
    );

    let directory = SessionFacts {
        directory: Some("crates".to_owned()),
        application: Some("nvim".to_owned()),
        ..SessionFacts::default()
    };
    assert_eq!(deterministic_title(&directory).as_str(), "crates");

    let application = SessionFacts {
        application: Some("nvim".to_owned()),
        ..SessionFacts::default()
    };
    assert_eq!(deterministic_title(&application).as_str(), "nvim");

    assert_eq!(
        deterministic_title(&SessionFacts::default()).as_str(),
        "Session"
    );
}

/// KR-REQ-22.02: a verified status is built from host facts and answers the pressing thing first.
#[test]
fn a_verified_status_comes_from_host_facts_and_names_what_is_waiting() {
    let running = LifecycleFacts {
        started: true,
        reachable: true,
        ..LifecycleFacts::default()
    };
    assert_eq!(VerifiedStatus::of(&running), VerifiedStatus::Running);
    assert_eq!(
        VerifiedStatus::of(&LifecycleFacts {
            approval_outstanding: true,
            completed: true,
            ..running
        }),
        VerifiedStatus::AwaitingApproval
    );
    assert_eq!(
        VerifiedStatus::of(&LifecycleFacts {
            reachable: false,
            approval_outstanding: true,
            ..running
        }),
        VerifiedStatus::Unreachable
    );
    assert_eq!(
        VerifiedStatus::of(&LifecycleFacts {
            closed: true,
            ..running
        }),
        VerifiedStatus::Closed
    );
}

/// KR-REQ-22.03: two environments keep their own mapping, and a group grants neither the other's.
#[test]
fn a_logical_group_grants_no_transcript_access_and_no_shared_mapping() {
    let group = MachineGroup::new("Ricky's machines");
    assert!(!group.grants_transcript_access());
    let first = native(1).in_group(group.clone());
    let second = native(2).in_group(group);
    let profile = default_profile();
    let mut mapping = ModelMapping::new();
    mapping
        .map(&first, None, &profile, MAC, TimestampMs::new(1))
        .expect("the first environment maps");
    mapping
        .map(&second, None, &profile, MAC, TimestampMs::new(2))
        .expect("the second environment maps");
    assert_eq!(mapping.mapped_environments(), 2);
    assert!(mapping.accepts_result(first.id(), profile.profile_id(), profile.revision()));
    assert!(mapping.unloaded().is_empty());
}

/// KR-REQ-22.04: WSL runs no model until somebody explicitly chooses to let local data cross.
#[test]
fn wsl_runs_no_model_until_somebody_chooses_to_let_local_data_cross() {
    let wsl = ExecutionEnvironment::new(environment_id(7), EnvironmentKind::Wsl);
    assert_eq!(
        wsl.placement(None),
        Placement::Refused(PlacementRefusal::WslDataAccessNotChosen)
    );

    // A choice made for a different distribution is not this one's.
    let elsewhere = DataAccessChoice {
        environment_id: environment_id(8),
        chosen_by: kr_protocol::ids::ActorId::new("local:501").expect("an actor"),
        chosen_at_ms: TimestampMs::new(1),
    };
    assert_eq!(
        wsl.placement(Some(&elsewhere)),
        Placement::Refused(PlacementRefusal::WslDataAccessNotChosen)
    );

    let chosen = DataAccessChoice {
        environment_id: environment_id(7),
        ..elsewhere
    };
    assert_eq!(wsl.placement(Some(&chosen)), Placement::NativeHostBroker);
}

/// KR-REQ-22.06: MiniCPM5-2B is the default, and SmolLM3-3B is a gated candidate.
#[test]
fn the_default_profile_is_minicpm_and_smollm_is_a_gated_candidate() {
    let catalogue = built_in();
    let default = catalogue.default_profile();
    assert_eq!(default.model().repository, "openbmb/MiniCPM5-2B");
    assert_eq!(default.gate(), Gate::Default);
    assert!(default.gates().is_empty());

    let candidate = catalogue
        .profile("smollm3-3b-q4-k-m")
        .expect("the candidate is shipped");
    assert_eq!(candidate.model().repository, "HuggingFaceTB/SmolLM3-3B");
    assert_eq!(candidate.gate(), Gate::Candidate);
    assert_eq!(
        candidate.gates(),
        [
            QualificationGate::Platform,
            QualificationGate::Resource,
            QualificationGate::Quality
        ]
    );

    // With no gates met, the default is what a host runs.
    let selection = catalogue.select(MAC, &MetGates::default());
    assert_eq!(
        selection.profile().map(ModelProfile::profile_id),
        Some("minicpm5-2b-q4-k-m")
    );
}

/// KR-REQ-22.07: pressure, a timeout and bad output never select a larger model.
///
/// The proof is the selection's arguments. It takes a target and the gates an owner recorded, and
/// nothing else: there is no memory figure, no deadline and no previous failure it could branch on.
/// What a host under pressure does instead is pause, and its title falls back to metadata.
#[test]
fn pressure_a_timeout_and_bad_output_never_select_a_larger_model() {
    let catalogue = built_in();
    let chosen = |met: &MetGates| {
        catalogue
            .select(MAC, met)
            .profile()
            .map(|profile| profile.profile_id().to_owned())
    };
    assert_eq!(
        chosen(&MetGates::default()).as_deref(),
        Some("minicpm5-2b-q4-k-m")
    );

    // Even with every gate met, the default is still first in the catalogue and still chosen.
    let all = MetGates::new(vec![
        QualificationGate::Platform,
        QualificationGate::Resource,
        QualificationGate::Quality,
    ]);
    assert_eq!(chosen(&all).as_deref(), Some("minicpm5-2b-q4-k-m"));

    // A host on a target neither profile lists falls back to deterministic metadata rather than to
    // a bigger model.
    let Selection::DeterministicMetadata { reasons } =
        catalogue.select("mips64-unknown-linux-gnuabi64", &all)
    else {
        panic!("an unlisted target selects no profile");
    };
    assert_eq!(reasons.len(), 2);
    assert!(
        reasons
            .iter()
            .all(|(_, why)| matches!(why, NotSelected::IncompatibleTarget))
    );
}

/// KR-REQ-22.08: every shipped profile carries the identities section 22 names, and no GPU layer.
#[test]
fn every_shipped_profile_carries_the_identities_and_offloads_no_layer() {
    for profile in built_in().profiles() {
        assert!(!profile.model().model_revision.is_empty());
        assert!(!profile.model().source_revision.is_empty());
        assert!(!profile.conversion().revision.is_empty());
        assert_eq!(profile.runtime().binding, "llama-cpp-2");
        assert_eq!(profile.runtime().binding_version, "0.1.156");
        assert_eq!(profile.runtime().llama_cpp_revision.len(), 40);
        assert_eq!(profile.tokenizer().tokenizer_sha256.len(), 64);
        assert_eq!(profile.tokenizer().chat_template_sha256.len(), 64);
        assert!(profile.reasoning().is_disabled());
        assert!(!profile.components().tools);
        assert!(!profile.components().vision);
        assert_eq!(profile.execution().gpu_layers, 0);
        assert!(profile.sampler().is_greedy());
        assert!(profile.supports_target(MAC));
        for asset in profile.assets() {
            assert_eq!(asset.sha256.len(), 64);
            assert!(asset.bytes > 0);
        }
        // Accounting, not file size: the resident estimate is itemised and more than the weights.
        let cost = profile.execution().resident_estimate;
        assert_eq!(cost.weights_bytes, profile.asset_bytes());
        assert!(cost.kv_cache_bytes > 0);
        assert!(cost.batch_bytes > 0);
        assert!(cost.runtime_overhead_bytes > 0);
        assert!(cost.beyond_the_weights() > 100 * 1024 * 1024);
        assert!(Budgets::DEFAULTS.admits(&cost));
    }
}

/// KR-REQ-22.08: a profile from outside the binary is used only when its signature verifies.
#[test]
fn a_profile_from_outside_the_binary_needs_a_signature_this_host_accepts() {
    let keys = kr_crypto::keys::AuthorisationKeyPair::generate().expect("a keypair");
    let other = kr_crypto::keys::AuthorisationKeyPair::generate().expect("another keypair");
    let document = ProfileDocument::new(catalogue::DEFAULT_PROFILE_DOCUMENT.as_bytes().to_vec());
    let transcript = document.transcript().expect("a transcript");
    let signature = kr_crypto::sign::sign(&keys, &transcript).expect("a signature");
    let trust = ProfileTrust::new(vec![*keys.public()]);

    let signed = SignedProfile {
        document: document.clone(),
        key: *keys.public(),
        signature,
    };
    let verified = trust.verify(&signed).expect("a signed profile verifies");
    assert_eq!(verified.profile_id(), "minicpm5-2b-q4-k-m");

    // A key this host does not accept.
    let untrusted = ProfileTrust::new(vec![*other.public()]);
    assert!(matches!(
        untrusted.verify(&signed),
        Err(DescribeError::ProfileUntrustedKey)
    ));

    // One byte of the document changed, with the same signature.
    let mut bytes = catalogue::DEFAULT_PROFILE_DOCUMENT.as_bytes().to_vec();
    let position = bytes
        .windows(2)
        .position(|pair| pair == b"20")
        .expect("the document names a revision");
    bytes[position] = b'3';
    let tampered = SignedProfile {
        document: ProfileDocument::new(bytes),
        key: signed.key,
        signature,
    };
    assert!(matches!(
        trust.verify(&tampered),
        Err(DescribeError::ProfileSignatureInvalid)
    ));

    // An empty trust set accepts nothing at all.
    assert!(ProfileTrust::default().is_empty());
    assert!(matches!(
        ProfileTrust::default().verify(&signed),
        Err(DescribeError::ProfileUntrustedKey)
    ));
}

/// KR-REQ-22.08: a profile that states something this product will not run is refused.
#[test]
fn a_profile_that_offloads_a_layer_or_carries_a_component_is_refused() {
    let refuse = |find: &str, replace: &str| {
        let document = catalogue::DEFAULT_PROFILE_DOCUMENT.replace(find, replace);
        ModelProfile::parse(document.as_bytes())
    };
    assert!(matches!(
        refuse("\"gpu_layers\": 0", "\"gpu_layers\": 32"),
        Err(DescribeError::ProfileRefused { .. })
    ));
    assert!(matches!(
        refuse("\"tools\": false", "\"tools\": true"),
        Err(DescribeError::ProfileRefused { .. })
    ));
    assert!(matches!(
        refuse("\"vision\": false", "\"vision\": true"),
        Err(DescribeError::ProfileRefused { .. })
    ));
    assert!(matches!(
        refuse("\"mode\": \"disabled\"", "\"mode\": \"thinking\""),
        Err(DescribeError::ProfileRefused { .. })
    ));
    // A field this build does not know is a profile it cannot claim to understand.
    assert!(matches!(
        refuse(
            "\"gate\": \"default\"",
            "\"gate\": \"default\", \"speculative\": true"
        ),
        Err(DescribeError::ProfileMalformed { .. })
    ));
}

/// KR-REQ-22.08: two profiles never share a tokenizer or a chat template.
#[test]
fn two_models_never_share_a_tokenizer_or_a_chat_template() {
    let catalogue = built_in();
    let default = catalogue.default_profile();
    let candidate = catalogue
        .profile("smollm3-3b-q4-k-m")
        .expect("the candidate");
    assert_ne!(
        default.tokenizer().tokenizer_sha256,
        candidate.tokenizer().tokenizer_sha256
    );
    assert_ne!(
        default.tokenizer().chat_template_sha256,
        candidate.tokenizer().chat_template_sha256
    );

    let shared = catalogue::CANDIDATE_PROFILE_DOCUMENT.replace(
        &candidate.tokenizer().tokenizer_sha256,
        &default.tokenizer().tokenizer_sha256,
    );
    let sharing = ModelProfile::parse(shared.as_bytes()).expect("it still parses");
    assert!(matches!(
        Catalogue::new(vec![default.clone(), sharing]),
        Err(DescribeError::CatalogueRefused { .. })
    ));
}

/// KR-REQ-22.09: one download per selected profile, under a disclosed policy, and never both.
#[test]
fn one_download_per_selected_profile_and_never_the_other_one() {
    let catalogue = built_in();
    let selected = catalogue.default_profile();
    let candidate = catalogue
        .profile("smollm3-3b-q4-k-m")
        .expect("the candidate");
    let policy = DownloadPolicy::of(selected);
    assert_eq!(policy.bytes, selected.asset_bytes());
    assert_eq!(policy.sources, vec!["huggingface.co".to_owned()]);

    let mut ledger = DownloadLedger::new();
    assert!(matches!(
        ledger.admit(selected, selected).expect("the first fetch"),
        Admission::Download(_)
    ));
    assert_eq!(
        ledger
            .admit(selected, selected)
            .expect("the second request"),
        Admission::AlreadyHeld
    );
    assert_eq!(ledger.downloads(), 1);
    assert!(matches!(
        ledger.admit(selected, candidate),
        Err(DescribeError::DownloadNotSelected { .. })
    ));
    assert_eq!(ledger.downloads(), 1);
}

/// KR-REQ-22.09: an asset that is not the recorded one is refused by size and by digest.
#[test]
fn an_asset_that_is_not_the_recorded_file_is_refused() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let profile = default_profile();
    let asset = &profile.assets()[0];
    let path = directory.path().join(&asset.file_name);
    std::fs::write(&path, b"not two gigabytes of weights").expect("a file");
    assert!(matches!(
        asset.verify_file(&path),
        Err(DescribeError::AssetSizeMismatch { .. })
    ));

    // A file of the right size and the wrong contents is refused by the digest.
    let document = catalogue::DEFAULT_PROFILE_DOCUMENT
        .replace(&asset.bytes.to_string(), "28")
        .replace(
            &format!("\"weights_bytes\": {}", asset.bytes),
            "\"weights_bytes\": 28",
        );
    let small = ModelProfile::parse(document.as_bytes()).expect("a profile with a small asset");
    assert!(matches!(
        small.assets()[0].verify_file(&path),
        Err(DescribeError::AssetDigestMismatch { .. })
    ));

    assert!(matches!(
        asset.verify_file(&directory.path().join("absent.gguf")),
        Err(DescribeError::AssetUnreadable { .. })
    ));
}

/// KR-REQ-22.09: a replaced model is unloaded before another is mapped.
#[test]
fn a_replaced_model_is_unloaded_before_another_is_mapped() {
    let catalogue = built_in();
    let first = catalogue.default_profile().clone();
    let second = catalogue
        .profile("smollm3-3b-q4-k-m")
        .expect("the candidate")
        .clone();
    let environment = native(1);
    let mut mapping = ModelMapping::new();
    mapping
        .map(&environment, None, &first, MAC, TimestampMs::new(1))
        .expect("the first mapping");
    let remapped = mapping
        .map(&environment, None, &second, MAC, TimestampMs::new(2))
        .expect("the second mapping");
    assert_eq!(
        remapped.unloaded.map(|mapped| mapped.profile_id),
        Some(first.profile_id().to_owned())
    );
    assert_eq!(mapping.mapped_environments(), 1);
    assert_eq!(mapping.unloaded().len(), 1);

    // And a result from the first profile is no longer accepted.
    assert!(!mapping.accepts_result(environment.id(), first.profile_id(), first.revision()));
    assert!(mapping.accepts_result(environment.id(), second.profile_id(), second.revision()));
}

/// KR-REQ-22.10: the defaults are section 22's, and the cost accounted for is not the file size.
#[test]
fn the_defaults_are_section_22s_and_the_cost_is_more_than_the_file() {
    let budgets = Budgets::DEFAULTS;
    assert_eq!(budgets.cpu_threads, 4);
    assert_eq!(budgets.active_requests, 1);
    assert_eq!(budgets.context_tokens, 4096);
    assert_eq!(budgets.max_output_tokens, 128);
    assert_eq!(budgets.context_debounce_ms, 2_000);
    assert_eq!(budgets.session_cooldown_ms, 30_000);
    assert_eq!(budgets.process_memory_ceiling_bytes, 4 * GIB);
    assert_eq!(budgets.execution_deadline_ms, 30_000);

    let profile = default_profile();
    let cost = profile.execution().resident_estimate;
    assert!(cost.total() > profile.asset_bytes());
    assert!(!budgets.admits(&ResidentCost {
        weights_bytes: 4 * GIB,
        ..cost
    }));
}

/// KR-REQ-22.10: an owner may tighten the ceiling and never loosen it.
#[test]
fn an_owner_may_tighten_the_ceiling_and_never_loosen_it() {
    assert_eq!(
        Budgets::DEFAULTS
            .with_owner_ceiling(2 * GIB)
            .process_memory_ceiling_bytes,
        2 * GIB
    );
    assert_eq!(
        Budgets::DEFAULTS
            .with_owner_ceiling(16 * GIB)
            .process_memory_ceiling_bytes,
        4 * GIB
    );
}
