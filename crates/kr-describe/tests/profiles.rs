//! Section 22's floor and its profiles: a title on every host, where a model may be mapped, and
//! what a signed profile has to say before anything is loaded.
//!
//! Nothing here needs a runtime, a queue or a store. That is the point of the section these tests
//! cover: a host with no model at all still names and orders every session, and a profile is a
//! statement that can be checked before a byte of it is fetched.

mod support;

use kr_crypto::keys::AuthorisationKeyPair;
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
use kr_describe::profile::catalogue::builtin_trust;
use kr_describe::profile::catalogue::{Catalogue, MetGates, NotSelected, Selection};
use kr_describe::profile::{
    Admission, DownloadLedger, DownloadPolicy, Gate, ModelProfile, ProfileDocument, ProfileTrust,
    QualificationGate, SignedProfile, catalogue,
};
use kr_protocol::scalars::TimestampMs;

use support::{MAC, built_in, default_profile, environment_id, native};

/// Signs a profile document with a test key, which is the only way to get a [`ModelProfile`].
fn sign(document: &str, keys: &AuthorisationKeyPair) -> SignedProfile {
    let document = ProfileDocument::new(document.as_bytes().to_vec());
    let transcript = document.transcript().expect("a transcript");
    let signature = kr_crypto::sign::sign(keys, &transcript).expect("a signature");
    SignedProfile {
        document,
        key: *keys.public(),
        signature,
    }
}

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
        .map(
            &first,
            None,
            &profile,
            &MetGates::default(),
            MAC,
            TimestampMs::new(1),
        )
        .expect("the first environment maps");
    mapping
        .map(
            &second,
            None,
            &profile,
            &MetGates::default(),
            MAC,
            TimestampMs::new(2),
        )
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
        assert!(!profile.model().revision.is_empty());
        assert!(profile.conversion().converter_revision.is_none());
        assert!(profile.tokenizer().embedded_in_asset);
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

/// KR-REQ-22.08: a profile is used only when a key this host accepts signed the exact document.
#[test]
fn a_profile_is_used_only_when_a_key_this_host_accepts_signed_it() {
    let keys = kr_crypto::keys::AuthorisationKeyPair::generate().expect("a keypair");
    let other = kr_crypto::keys::AuthorisationKeyPair::generate().expect("another keypair");
    let trust = ProfileTrust::new(vec![*keys.public()]);
    let signed = sign(catalogue::DEFAULT_PROFILE_DOCUMENT, &keys);

    let verified = trust.verify(&signed).expect("a signed profile verifies");
    assert_eq!(verified.profile_id(), "minicpm5-2b-q4-k-m");

    // A key this host does not accept.
    let untrusted = ProfileTrust::new(vec![*other.public()]);
    assert!(matches!(
        untrusted.verify(&signed),
        Err(DescribeError::ProfileUntrustedKey)
    ));

    // One byte of the document changed, with the same signature.
    let tampered = SignedProfile {
        document: ProfileDocument::new(
            catalogue::DEFAULT_PROFILE_DOCUMENT
                .replace(
                    "\"parameters_billions\": 2.0",
                    "\"parameters_billions\": 3.0",
                )
                .into_bytes(),
        ),
        ..signed.clone()
    };
    assert!(matches!(
        trust.verify(&tampered),
        Err(DescribeError::ProfileSignatureInvalid)
    ));

    // A signature made over a different document, presented for this one.
    let swapped = SignedProfile {
        signature: sign(catalogue::CANDIDATE_PROFILE_DOCUMENT, &keys).signature,
        ..signed.clone()
    };
    assert!(matches!(
        trust.verify(&swapped),
        Err(DescribeError::ProfileSignatureInvalid)
    ));

    // An empty trust set accepts nothing at all.
    assert!(ProfileTrust::default().is_empty());
    assert!(matches!(
        ProfileTrust::default().verify(&signed),
        Err(DescribeError::ProfileUntrustedKey)
    ));

    // And the profiles this build ships verify against this build's own anchor.
    let builtin = builtin_trust().expect("this build has an anchor");
    assert_eq!(builtin.len(), 1);
    assert!(built_in().profiles().len() == 2);
}

/// KR-REQ-22.08: a signed document that states something this product will not run is refused.
///
/// Every case goes through the signature, because that is the only door: a document is checked
/// after its signature verifies, so a profile refused here is one a correctly signed document
/// could have carried.
#[test]
fn a_signed_profile_that_states_the_wrong_thing_is_still_refused() {
    let keys = kr_crypto::keys::AuthorisationKeyPair::generate().expect("a keypair");
    let trust = ProfileTrust::new(vec![*keys.public()]);
    let refuse = |find: &str, replace: &str| {
        let document = catalogue::DEFAULT_PROFILE_DOCUMENT.replace(find, replace);
        assert_ne!(
            document,
            catalogue::DEFAULT_PROFILE_DOCUMENT,
            "the case changed nothing"
        );
        trust.verify(&sign(&document, &keys))
    };
    for (find, replace) in [
        ("\"gpu_layers\": 0", "\"gpu_layers\": 32"),
        ("\"tools\": false", "\"tools\": true"),
        ("\"vision\": false", "\"vision\": true"),
        ("\"mode\": \"disabled\"", "\"mode\": \"thinking\""),
        ("\"temperature\": 0.0", "\"temperature\": -1.0"),
        ("\"top_p\": 1.0", "\"top_p\": 4.0"),
        ("\"top_k\": 1", "\"top_k\": 0"),
        ("\"context_tokens\": 4096", "\"context_tokens\": 0"),
        ("\"max_output_tokens\": 128", "\"max_output_tokens\": 8192"),
        ("\"cpu_threads\": 4", "\"cpu_threads\": 0"),
        (
            "\"revision\": \"12a3808a956f869c767195e9266b59c4d21d92e2\"",
            "\"revision\": \"\"",
        ),
        ("\"role\": \"weights\"", "\"role\": \"tokenizer\""),
        (
            "\"tokenizer_sha256\": \"3e065a558a034185fe299917b398685c1facd0169a9eea1e629eb30c171fed81\"",
            "\"tokenizer_sha256\": \"NOTAHASH\"",
        ),
        ("\"gate\": \"default\"", "\"gate\": \"candidate\""),
    ] {
        assert!(
            matches!(
                refuse(find, replace),
                Err(DescribeError::ProfileRefused { .. })
            ),
            "{find} -> {replace} was not refused"
        );
    }

    // A field this build does not know is a document it cannot claim to understand.
    assert!(matches!(
        refuse(
            "\"gate\": \"default\"",
            "\"gate\": \"default\", \"speculative\": true"
        ),
        Err(DescribeError::ProfileMalformed { .. })
    ));

    // A candidate that declares fewer than all three gates is refused too.
    let fewer = catalogue::CANDIDATE_PROFILE_DOCUMENT.replace(
        "\"platform\",\n    \"resource\",\n    \"quality\"",
        "\"platform\"",
    );
    assert!(matches!(
        trust.verify(&sign(&fewer, &keys)),
        Err(DescribeError::ProfileRefused { .. })
    ));
}

/// KR-REQ-22.08: each model names its own tokenizer and chat template rather than borrowing one.
#[test]
fn each_model_names_its_own_tokenizer_and_chat_template() {
    let catalogue = built_in();
    for profile in catalogue.profiles() {
        assert_eq!(
            profile.tokenizer().source_repository,
            profile.model().repository,
            "a profile's tokenizer comes from its own model"
        );
        assert_eq!(
            profile.tokenizer().source_revision,
            profile.model().revision
        );
        // The digests are provenance; what inference reads is embedded in the asset, and the asset
        // digest is what pins it.
        assert!(profile.tokenizer().embedded_in_asset);
    }
    let default = catalogue.default_profile();
    let candidate = catalogue
        .profile("smollm3-3b-q4-k-m")
        .expect("the candidate");
    assert_ne!(
        default.tokenizer().tokenizer_sha256,
        candidate.tokenizer().tokenizer_sha256
    );
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
    // Nothing is held while the fetch is running, so a second request does not start another and
    // does not claim the assets are there.
    assert!(ledger.is_running(selected.profile_id(), selected.revision()));
    assert!(!ledger.holds(selected.profile_id(), selected.revision()));
    assert_eq!(
        ledger
            .admit(selected, selected)
            .expect("the second request"),
        Admission::AlreadyRunning
    );
    assert_eq!(ledger.downloads(), 0);

    ledger.note_verified(selected);
    assert!(ledger.holds(selected.profile_id(), selected.revision()));
    assert_eq!(
        ledger
            .admit(selected, selected)
            .expect("a request afterwards"),
        Admission::AlreadyHeld
    );
    assert_eq!(ledger.downloads(), 1);

    // A profile this environment did not select is refused outright.
    assert!(matches!(
        ledger.admit(selected, candidate),
        Err(DescribeError::DownloadNotSelected { .. })
    ));
    assert_eq!(ledger.downloads(), 1);
}

/// KR-REQ-22.09: a cancelled or failed fetch leaves nothing held, so the next request fetches.
#[test]
fn a_cancelled_or_failed_fetch_leaves_nothing_held() {
    let catalogue = built_in();
    let selected = catalogue.default_profile();
    let mut ledger = DownloadLedger::new();
    ledger.admit(selected, selected).expect("a fetch");
    ledger.note_failed(selected);
    assert!(!ledger.holds(selected.profile_id(), selected.revision()));
    assert!(!ledger.is_running(selected.profile_id(), selected.revision()));
    assert_eq!(ledger.downloads(), 0);
    assert!(matches!(
        ledger.admit(selected, selected).expect("the next fetch"),
        Admission::Download(_)
    ));

    // A verified fetch that is later found wrong is released the same way.
    ledger.note_verified(selected);
    assert!(ledger.holds(selected.profile_id(), selected.revision()));
    ledger.note_failed(selected);
    assert!(!ledger.holds(selected.profile_id(), selected.revision()));
}

/// KR-REQ-22.09: an asset that is not the recorded file is refused by size and by digest.
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
    assert!(matches!(
        asset.verify_file(&directory.path().join("absent.gguf")),
        Err(DescribeError::AssetUnreadable { .. })
    ));

    // A file larger than one digest block, so the streaming path is the one under test. The
    // profile is rewritten to describe this file exactly, and then one byte of it is changed.
    let body = vec![0x5a_u8; (1 << 20) + 4096];
    let digest = {
        use sha2::Digest as _;
        let mut hasher = sha2::Sha256::new();
        hasher.update(&body);
        hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let keys = kr_crypto::keys::AuthorisationKeyPair::generate().expect("a keypair");
    let trust = ProfileTrust::new(vec![*keys.public()]);
    let document = catalogue::DEFAULT_PROFILE_DOCUMENT
        .replace(&asset.sha256, &digest)
        .replace(&asset.bytes.to_string(), &body.len().to_string());
    let rewritten = trust
        .verify(&sign(&document, &keys))
        .expect("a profile over the file this test wrote");
    let big = directory.path().join(&rewritten.assets()[0].file_name);
    std::fs::write(&big, &body).expect("a large file");
    rewritten.assets()[0]
        .verify_file(&big)
        .expect("a file that matches across several blocks verifies");

    let mut changed = body.clone();
    changed[(1 << 20) + 1] = 0x5b;
    std::fs::write(&big, &changed).expect("a changed file");
    assert!(matches!(
        rewritten.assets()[0].verify_file(&big),
        Err(DescribeError::AssetDigestMismatch { .. })
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
        .map(
            &environment,
            None,
            &first,
            &MetGates::all(),
            MAC,
            TimestampMs::new(1),
        )
        .expect("the first mapping");
    let remapped = mapping
        .map(
            &environment,
            None,
            &second,
            &MetGates::all(),
            MAC,
            TimestampMs::new(2),
        )
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

/// KR-REQ-22.06: the default is chosen whatever order the catalogue was built from.
#[test]
fn the_default_is_chosen_whatever_order_the_catalogue_was_built_from() {
    let catalogue = built_in();
    let default = catalogue.default_profile().clone();
    let candidate = catalogue
        .profile("smollm3-3b-q4-k-m")
        .expect("the candidate")
        .clone();
    let reversed = Catalogue::new(vec![candidate, default]).expect("a catalogue either way");
    assert_eq!(
        reversed.default_profile().profile_id(),
        "minicpm5-2b-q4-k-m"
    );
    assert_eq!(
        reversed
            .select(MAC, &MetGates::all())
            .profile()
            .map(ModelProfile::profile_id),
        Some("minicpm5-2b-q4-k-m"),
        "every gate met still selects the default"
    );
}

/// KR-REQ-22.07: a candidate cannot be mapped without the gates it declares, however it was
/// obtained.
#[test]
fn a_candidate_cannot_be_mapped_without_the_gates_it_declares() {
    let catalogue = built_in();
    let candidate = catalogue
        .profile("smollm3-3b-q4-k-m")
        .expect("the candidate");
    let environment = native(1);
    let mut mapping = ModelMapping::new();
    assert!(matches!(
        mapping.map(
            &environment,
            None,
            candidate,
            &MetGates::default(),
            MAC,
            TimestampMs::new(1)
        ),
        Err(DescribeError::GatesOutstanding { .. })
    ));
    assert_eq!(mapping.mapped_environments(), 0);
    assert!(
        mapping
            .map(
                &environment,
                None,
                candidate,
                &MetGates::all(),
                MAC,
                TimestampMs::new(2)
            )
            .is_ok()
    );
}
