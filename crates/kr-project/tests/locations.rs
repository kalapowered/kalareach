//! The owner's authorised locations: the policy, the held handles, the confirmation each decision
//! needs and the binding of a repository to the source it is read through.
//!
//! KR-REQ-23.42 and 23.43 (the policy half: every name this host resolves through a location
//! descends from a handle the owner authorised), KR-REQ-14.06.
//!
//! The daemon's owner is stood in by [`support::TestOwner`], which issues and consumes challenges
//! the way the daemon's ceremony does; the ceremony's own cryptography is proved through the real
//! daemon in `kr-controller`'s suite.
//!
//! Every kr-project suite runs where the service runs Git, which Windows refuses outright; the
//! refusal itself is in `tests/boundary.rs`.

#![cfg(not(windows))]
#![cfg(feature = "git-fixtures")]

mod support;

use std::path::Path;

use kr_project::ProjectService;
use kr_project::policy::{Admitting, LocationUse};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{EnvironmentId, GrantId, ProjectLocationId, ProjectRepositoryId};
use kr_protocol::pairing::OwnerConfirmationRequest;
use kr_protocol::project::{
    AdoptionFlow, AuthorisedLocation, LocationAttachment, LocationAuthorisation, LocationPurpose,
    LocationState, ProjectAdoptParams, ProjectLocationAttachParams, ProjectLocationAttachResult,
    ProjectLocationAuthoriseParams, ProjectLocationListParams, ProjectLocationWithdrawParams,
};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{Nullable, Uuid};

use support::{
    Fixture, TestOwner, action, actor, destination, ordinary_repository, sign, submission,
};

const AUTHORISE: &str = "project.location.authorise";
const ATTACH: &str = "project.location.attach";
const WITHDRAW: &str = "project.location.withdraw";

fn authorise_params(
    environment_id: EnvironmentId,
    path: &Path,
    purpose: LocationPurpose,
    grant: Option<GrantId>,
) -> ProjectLocationAuthoriseParams {
    ProjectLocationAuthoriseParams {
        location_id: Nullable(None),
        environment_id,
        grant_id: Nullable(grant),
        purpose,
        label: "a place the owner chose".to_owned(),
        path: path.display().to_string(),
        owner_confirmation: Nullable(None),
    }
}

/// Asks for a challenge, expecting one.
fn challenge_for(
    service: &ProjectService,
    owner: &TestOwner,
    params: &ProjectLocationAuthoriseParams,
    seed: u8,
) -> OwnerConfirmationRequest {
    let answered = service
        .project_location_authorise(
            &actor(),
            params,
            Some(&submission(AUTHORISE, seed, false)),
            Some(owner),
        )
        .expect("the first submission is answered");
    match answered.outcome {
        LocationAuthorisation::ConfirmationRequired { request } => request,
        LocationAuthorisation::Authorised { .. } => {
            panic!("a first submission with no proof authorises nothing")
        }
    }
}

/// Submits the same action again with the owner's proof.
fn confirm(
    service: &ProjectService,
    owner: &TestOwner,
    params: &ProjectLocationAuthoriseParams,
    request: &OwnerConfirmationRequest,
    seed: u8,
) -> Result<AuthorisedLocation, kr_project::ProjectError> {
    let proven = ProjectLocationAuthoriseParams {
        owner_confirmation: Nullable(Some(sign(request))),
        ..params.clone()
    };
    let answered = service.project_location_authorise(
        &actor(),
        &proven,
        Some(&submission(AUTHORISE, seed, true)),
        Some(owner),
    )?;
    match answered.outcome {
        LocationAuthorisation::Authorised { location } => Ok(location),
        LocationAuthorisation::ConfirmationRequired { .. } => {
            panic!("a submission carrying a proof is not answered with another challenge")
        }
    }
}

/// Authorises one location end to end.
fn authorised(
    service: &ProjectService,
    owner: &TestOwner,
    params: &ProjectLocationAuthoriseParams,
    seed: u8,
) -> AuthorisedLocation {
    let request = challenge_for(service, owner, params, seed);
    confirm(service, owner, params, &request, seed).expect("the confirmed authorisation succeeds")
}

fn adopt(fixture: &Fixture, parent: &Path, name: &str, seed: u8) -> ProjectRepositoryId {
    ordinary_repository(parent, name);
    fixture
        .service()
        .project_adopt(
            &actor(),
            &ProjectAdoptParams {
                destination: destination(fixture.environment_id(), parent, name),
                label: name.to_owned(),
                flow: AdoptionFlow::ExistingCheckout,
            },
            Some(&action("project.adopt", seed)),
        )
        .expect("the checkout is adopted")
        .project
        .project_repository_id
}

fn attach_params(
    project: ProjectRepositoryId,
    location: Option<ProjectLocationId>,
) -> ProjectLocationAttachParams {
    ProjectLocationAttachParams {
        project_repository_id: project,
        location_id: Nullable(location),
        owner_confirmation: Nullable(None),
    }
}

/// Binds a repository to a source location end to end, or returns the refusal.
fn attach(
    service: &ProjectService,
    owner: &TestOwner,
    project: ProjectRepositoryId,
    location: ProjectLocationId,
    seed: u8,
) -> Result<ProjectLocationAttachResult, kr_project::ProjectError> {
    let params = attach_params(project, Some(location));
    let first = service.project_location_attach(
        &actor(),
        &params,
        Some(&submission(ATTACH, seed, false)),
        Some(owner),
    )?;
    let LocationAttachment::ConfirmationRequired { request } = first.outcome else {
        panic!("a binding's first submission is answered with its challenge");
    };
    service.project_location_attach(
        &actor(),
        &ProjectLocationAttachParams {
            owner_confirmation: Nullable(Some(sign(&request))),
            ..params
        },
        Some(&submission(ATTACH, seed, true)),
        Some(owner),
    )
}

fn source_use(environment_id: EnvironmentId, admitting: Admitting) -> LocationUse {
    LocationUse {
        purpose: LocationPurpose::Source,
        environment_id,
        admitting,
    }
}

#[test]
fn an_owner_location_is_authorised_after_its_confirmation_and_not_before() {
    let fixture = Fixture::create();
    let owner = TestOwner::default();
    let root = fixture.work().join("projects");
    std::fs::create_dir(&root).expect("a directory to authorise");
    let params = authorise_params(
        fixture.environment_id(),
        &root,
        LocationPurpose::Destination,
        None,
    );
    let request = challenge_for(fixture.service(), &owner, &params, 1);
    // An owner location has no recipient device, and it carries both rights unintersected.
    assert!(request.destination_keys.0.is_none());
    assert_eq!(
        request.destination_rights,
        [ActionRight::ProjectCreate, ActionRight::WorkspaceManage]
            .into_iter()
            .collect()
    );
    // Nothing is authorised, and nothing is recorded, before the proof arrives.
    let listed = fixture
        .service()
        .project_location_list(&ProjectLocationListParams {
            environment_id: fixture.environment_id(),
            grant_id: Nullable(None),
        })
        .expect("the list reads");
    assert!(listed.locations.is_empty(), "{listed:?}");
    // A repeat of the same request is given the same challenge rather than a second one.
    let again = challenge_for(fixture.service(), &owner, &params, 1);
    assert_eq!(again, request);
    assert_eq!(owner.issued(), 1);

    let location = confirm(fixture.service(), &owner, &params, &request, 1)
        .expect("the confirmed authorisation succeeds");
    assert_eq!(location.state, LocationState::Active);
    assert_eq!(location.purpose, LocationPurpose::Destination);
    assert!(location.grant_id.0.is_none());
    assert_eq!(location.path, root.display().to_string());
    let listed = fixture
        .service()
        .project_location_list(&ProjectLocationListParams {
            environment_id: fixture.environment_id(),
            grant_id: Nullable(None),
        })
        .expect("the list reads");
    assert_eq!(listed.locations, vec![location]);
}

#[test]
fn authorisation_refuses_a_proof_for_anything_but_its_own_challenge() {
    let fixture = Fixture::create();
    let owner = TestOwner::default();
    let first = fixture.work().join("first");
    let second = fixture.work().join("second");
    std::fs::create_dir(&first).expect("a directory");
    std::fs::create_dir(&second).expect("a directory");
    let first_params = authorise_params(
        fixture.environment_id(),
        &first,
        LocationPurpose::Source,
        None,
    );
    let second_params = authorise_params(
        fixture.environment_id(),
        &second,
        LocationPurpose::Source,
        None,
    );
    let first_request = challenge_for(fixture.service(), &owner, &first_params, 3);
    let second_request = challenge_for(fixture.service(), &owner, &second_params, 4);

    // A proof for the other action's challenge answers nothing here.
    let crossed = confirm(fixture.service(), &owner, &first_params, &second_request, 3)
        .expect_err("a proof for another challenge is refused");
    assert_eq!(crossed.code(), ErrorCode::OwnerConfirmationRequired);

    // A proof with no challenge outstanding for its action is refused and records nothing.
    let unasked = confirm(fixture.service(), &owner, &first_params, &first_request, 5)
        .expect_err("an action that was never challenged has nothing to answer");
    assert_eq!(unasked.code(), ErrorCode::OwnerConfirmationRequired);

    // A signature that is not the owner's is refused by the ceremony, and the challenge stays
    // outstanding for the owner's own proof.
    let mut forged = sign(&first_request);
    forged.signature = kr_protocol::scalars::Signature64::from_bytes([0; 64]);
    let refused = fixture
        .service()
        .project_location_authorise(
            &actor(),
            &ProjectLocationAuthoriseParams {
                owner_confirmation: Nullable(Some(forged)),
                ..first_params.clone()
            },
            Some(&submission(AUTHORISE, 3, true)),
            Some(&owner),
        )
        .expect_err("a forged proof is refused");
    assert_eq!(refused.code(), ErrorCode::OwnerConfirmationRequired);

    // The same action's request, changed after the challenge was issued, is not the request the
    // owner confirmed.
    let changed = ProjectLocationAuthoriseParams {
        label: "a different label".to_owned(),
        ..first_params.clone()
    };
    let refused = confirm(fixture.service(), &owner, &changed, &first_request, 3)
        .expect_err("a changed request is not the confirmed one");
    assert_eq!(refused.code(), ErrorCode::OwnerConfirmationRequired);

    // None of that spent the challenge or recorded an answer.
    let location = confirm(fixture.service(), &owner, &first_params, &first_request, 3)
        .expect("the owner's own proof for the unchanged request authorises it");
    assert_eq!(location.path, first.display().to_string());

    // A proof that was spent is spent: the second action's challenge is still its own, and the
    // first action's proof replayed under it does not answer it.
    let replayed = confirm(fixture.service(), &owner, &second_params, &first_request, 4)
        .expect_err("a spent proof is refused under another action");
    assert_eq!(replayed.code(), ErrorCode::OwnerConfirmationRequired);

    // No owner, no authorisation.
    let unowned = fixture
        .service()
        .project_location_authorise(
            &actor(),
            &second_params,
            Some(&submission(AUTHORISE, 6, false)),
            None,
        )
        .expect_err("a host with no enrolled owner authorises nothing");
    assert_eq!(unowned.code(), ErrorCode::HostNotConfigured);
}

#[test]
fn location_matches_exact_grant_environment_and_purpose() {
    let fixture = Fixture::create();
    let owner = TestOwner::default();
    let grant = GrantId::new(Uuid::from_bytes([0x61; 16]));
    let root = fixture.work().join("shared");
    std::fs::create_dir(&root).expect("a directory to authorise");
    let environment = fixture.environment_id();

    let owners_source = authorised(
        fixture.service(),
        &owner,
        &authorise_params(environment, &root, LocationPurpose::Source, None),
        10,
    );
    let owners_destination = authorised(
        fixture.service(),
        &owner,
        &authorise_params(environment, &root, LocationPurpose::Destination, None),
        11,
    );

    let policy = fixture.service().locations();
    // The owner's source admits the owner's own read of a source, and the owner's decision.
    policy
        .admit(
            owners_source.location_id,
            &source_use(environment, Admitting::Caller(None)),
        )
        .expect("the owner's source admits the owner");
    policy
        .admit(
            owners_source.location_id,
            &source_use(environment, Admitting::OwnerDecision),
        )
        .expect("and the owner's decision about it");
    // Nothing else: another purpose, another environment, or a caller bounded by a grant.
    for wanted in [
        LocationUse {
            purpose: LocationPurpose::Destination,
            ..source_use(environment, Admitting::Caller(None))
        },
        source_use(
            EnvironmentId::new(Uuid::from_bytes([0x63; 16])),
            Admitting::Caller(None),
        ),
        source_use(environment, Admitting::Caller(Some(grant))),
    ] {
        let refusal = policy
            .admit(owners_source.location_id, &wanted)
            .expect_err("no other use is admitted");
        assert_eq!(refusal.code(), ErrorCode::PermissionDenied, "{wanted:?}");
    }
    // A destination is not a source, whoever asks.
    let refusal = policy
        .admit(
            owners_destination.location_id,
            &source_use(environment, Admitting::OwnerDecision),
        )
        .expect_err("a destination does not admit a source's read");
    assert_eq!(refusal.code(), ErrorCode::PermissionDenied);
}

#[test]
fn a_location_for_a_grant_is_not_authorised_and_nothing_is_issued_for_it() {
    // An owner's confirmation of a device's location has to name the keys of the device that
    // holds the grant, and this host keeps no complete set of them. So no such location is
    // authorised, no challenge is issued for one, and the refusal says why.
    let fixture = Fixture::create();
    let owner = TestOwner::default();
    let root = fixture.work().join("devices");
    std::fs::create_dir(&root).expect("a directory");
    let refusal = fixture
        .service()
        .project_location_authorise(
            &actor(),
            &authorise_params(
                fixture.environment_id(),
                &root,
                LocationPurpose::Source,
                Some(GrantId::new(Uuid::from_bytes([0x64; 16]))),
            ),
            Some(&submission(AUTHORISE, 12, false)),
            Some(&owner),
        )
        .expect_err("a grant's location is not authorised");
    assert_eq!(refusal.code(), ErrorCode::PermissionDenied);
    assert!(refusal.to_string().contains("keys"), "{refusal}");
    assert_eq!(owner.issued(), 0, "no challenge was issued for it");
}

#[test]
fn a_challenge_the_ledger_lets_go_is_dropped_with_its_directory() {
    let fixture = Fixture::create();
    let owner = TestOwner::default();
    let root = fixture.work().join("lapsing");
    std::fs::create_dir(&root).expect("a directory");
    let params = authorise_params(
        fixture.environment_id(),
        &root,
        LocationPurpose::Source,
        None,
    );
    let first = challenge_for(fixture.service(), &owner, &params, 13);
    // The ledger's own deadline ends the challenge, whatever any wall clock says. The service
    // lets go of it when asked, and a sweep lets go of it when nobody asks.
    owner.let_everything_go();
    assert_eq!(
        fixture
            .service()
            .expire_challenges(&owner)
            .expect("the sweep runs"),
        1,
        "the challenge the ledger let go is dropped, with the directory it held"
    );
    let refusal = confirm(fixture.service(), &owner, &params, &first, 13)
        .expect_err("a challenge that ran out answers nothing");
    assert_eq!(refusal.code(), ErrorCode::OwnerConfirmationRequired);
    // A repeat of the request is given a fresh challenge rather than the one that ran out.
    let second = challenge_for(fixture.service(), &owner, &params, 13);
    assert_ne!(second, first);
    confirm(fixture.service(), &owner, &params, &second, 13)
        .expect("the fresh challenge's proof authorises the location");
}

#[test]
fn the_challenge_bound_refuses_before_anything_is_issued() {
    let fixture = Fixture::create();
    let owner = TestOwner::default();
    let environment = fixture.environment_id();
    let bound = kr_project::policy::MAX_OUTSTANDING_CHALLENGES;
    for index in 0..bound {
        let directory = fixture.work().join(format!("held-{index}"));
        std::fs::create_dir(&directory).expect("a directory");
        let seed = u8::try_from(100 + index).expect("a seed");
        challenge_for(
            fixture.service(),
            &owner,
            &authorise_params(environment, &directory, LocationPurpose::Source, None),
            seed,
        );
    }
    let issued = owner.issued();
    let beyond = fixture.work().join("beyond");
    std::fs::create_dir(&beyond).expect("a directory");
    let refusal = fixture
        .service()
        .project_location_authorise(
            &actor(),
            &authorise_params(environment, &beyond, LocationPurpose::Source, None),
            Some(&submission(AUTHORISE, 99, false)),
            Some(&owner),
        )
        .expect_err("the bound refuses another challenge");
    assert_eq!(refusal.code(), ErrorCode::QuotaExceeded);
    assert_eq!(
        owner.issued(),
        issued,
        "a refused challenge was never issued"
    );
    assert_eq!(owner.outstanding(), bound);
}

#[test]
fn a_challenge_that_lapses_after_its_proof_is_verified_leaves_the_action_answered() {
    // The action is claimed before the challenge is spent, so a spend that fails is this action's
    // answer: a repeat is told what happened rather than that there is no challenge to answer.
    let fixture = Fixture::create();
    let owner = TestOwner::default();
    let root = fixture.work().join("lapse");
    std::fs::create_dir(&root).expect("a directory");
    let params = authorise_params(
        fixture.environment_id(),
        &root,
        LocationPurpose::Destination,
        None,
    );
    let request = challenge_for(fixture.service(), &owner, &params, 14);
    owner.lapse_after_verifying();
    let refusal = confirm(fixture.service(), &owner, &params, &request, 14)
        .expect_err("the challenge lapsed before it could be spent");
    assert_eq!(refusal.code(), ErrorCode::OwnerConfirmationRequired);
    let repeated = confirm(fixture.service(), &owner, &params, &request, 14)
        .expect_err("the repeat is given the kept answer");
    assert_eq!(repeated.code(), refusal.code());
    assert_eq!(repeated.to_string(), refusal.to_string());
    assert!(
        fixture
            .service()
            .project_location_list(&ProjectLocationListParams {
                environment_id: fixture.environment_id(),
                grant_id: Nullable(None),
            })
            .expect("the list reads")
            .locations
            .is_empty(),
        "nothing was authorised"
    );
}

#[test]
fn withdrawal_takes_a_location_out_of_every_later_admission_and_is_final() {
    let fixture = Fixture::create();
    let owner = TestOwner::default();
    let root = fixture.work().join("withdrawn");
    std::fs::create_dir(&root).expect("a directory to authorise");
    let environment = fixture.environment_id();
    let location = authorised(
        fixture.service(),
        &owner,
        &authorise_params(environment, &root, LocationPurpose::Source, None),
        20,
    );
    let wanted = source_use(environment, Admitting::Caller(None));
    let held = fixture
        .service()
        .locations()
        .admit(location.location_id, &wanted)
        .expect("an admission before the withdrawal");
    let withdrawn = fixture
        .service()
        .project_location_withdraw(
            &ProjectLocationWithdrawParams {
                location_id: location.location_id,
            },
            Some(&action(WITHDRAW, 21)),
        )
        .expect("the owner withdraws it");
    assert_eq!(withdrawn.location.state, LocationState::Withdrawn);
    assert!(withdrawn.location.withdrawn_at_ms.0.is_some());
    // A read admitted before the commit keeps the handle it was given.
    held.handle()
        .revalidate()
        .expect("an admitted read finishes on the handle it holds");
    // No read is admitted after it.
    let refusal = fixture
        .service()
        .locations()
        .admit(location.location_id, &wanted)
        .expect_err("nothing is admitted after a withdrawal");
    assert_eq!(refusal.code(), ErrorCode::PermissionDenied);
    // A withdrawal is final: authorising the identifier again is refused, before and after a
    // restart.
    let again = ProjectLocationAuthoriseParams {
        location_id: Nullable(Some(location.location_id)),
        ..authorise_params(environment, &root, LocationPurpose::Source, None)
    };
    let refusal = fixture
        .service()
        .project_location_authorise(
            &actor(),
            &again,
            Some(&submission(AUTHORISE, 22, false)),
            Some(&owner),
        )
        .expect_err("a withdrawn location is never authorised again");
    assert_eq!(refusal.code(), ErrorCode::PermissionDenied);
    let replacement = fixture.reopen();
    let refusal = replacement
        .project_location_authorise(
            &actor(),
            &again,
            Some(&submission(AUTHORISE, 23, false)),
            Some(&owner),
        )
        .expect_err("a restart does not revive a withdrawal");
    assert_eq!(refusal.code(), ErrorCode::PermissionDenied);
    let listed = replacement
        .project_location_list(&ProjectLocationListParams {
            environment_id: environment,
            grant_id: Nullable(None),
        })
        .expect("the list reads");
    assert_eq!(listed.locations.len(), 1);
    assert_eq!(listed.locations[0].state, LocationState::Withdrawn);
}

#[test]
fn reauthorisation_restores_a_dormant_location_in_place() {
    let fixture = Fixture::create();
    let owner = TestOwner::default();
    let root = fixture.work().join("sources");
    std::fs::create_dir(&root).expect("a directory to authorise");
    let environment = fixture.environment_id();
    let params = authorise_params(environment, &root, LocationPurpose::Source, None);
    let location = authorised(fixture.service(), &owner, &params, 30);
    let project = adopt(&fixture, &root, "repo", 31);
    attach(fixture.service(), &owner, project, location.location_id, 32)
        .expect("the repository is bound to the location");

    // A replacement daemon holds no handle, so the location is dormant and admits nothing.
    let replacement = fixture.reopen();
    let listed = replacement
        .project_location_list(&ProjectLocationListParams {
            environment_id: environment,
            grant_id: Nullable(None),
        })
        .expect("the list reads");
    assert_eq!(listed.locations[0].state, LocationState::Dormant);
    let wanted = source_use(environment, Admitting::Caller(None));
    replacement
        .locations()
        .admit(location.location_id, &wanted)
        .expect_err("a dormant location admits nothing");

    // Authorising the identifier again restores the same row, under a fresh confirmation.
    let again = ProjectLocationAuthoriseParams {
        location_id: Nullable(Some(location.location_id)),
        ..params.clone()
    };
    let restored = authorised(&replacement, &owner, &again, 33);
    assert_eq!(restored.location_id, location.location_id);
    assert_eq!(restored.state, LocationState::Active);
    replacement
        .locations()
        .admit(location.location_id, &wanted)
        .expect("the restored location admits its reads again");
    // The binding that names it works as it did.
    let rebound = attach(&replacement, &owner, project, location.location_id, 34)
        .expect("a repository bound to the restored location is reached through it");
    assert!(matches!(rebound.outcome, LocationAttachment::Bound { .. }));

    // An active location is not authorised again, and the identifier cannot change its kind.
    let refusal = replacement
        .project_location_authorise(
            &actor(),
            &again,
            Some(&submission(AUTHORISE, 35, false)),
            Some(&owner),
        )
        .expect_err("an active location is withdrawn before anything replaces it");
    assert_eq!(refusal.code(), ErrorCode::InvalidArgument);
    let later = fixture.reopen();
    drop(replacement);
    let refusal = later
        .project_location_authorise(
            &actor(),
            &ProjectLocationAuthoriseParams {
                purpose: LocationPurpose::Destination,
                ..again.clone()
            },
            Some(&submission(AUTHORISE, 36, false)),
            Some(&owner),
        )
        .expect_err("a source does not become a destination by being authorised again");
    assert_eq!(refusal.code(), ErrorCode::InvalidArgument);
    let refusal = later
        .project_location_authorise(
            &actor(),
            &ProjectLocationAuthoriseParams {
                location_id: Nullable(Some(ProjectLocationId::new(Uuid::from_bytes([0x71; 16])))),
                ..params
            },
            Some(&submission(AUTHORISE, 37, false)),
            Some(&owner),
        )
        .expect_err("an identifier this environment never had is refused");
    assert_eq!(refusal.code(), ErrorCode::ResourceUnavailable);
}

#[test]
fn replaced_location_is_refused_before_and_after_restart() {
    let fixture = Fixture::create();
    let owner = TestOwner::default();
    let root = fixture.work().join("root");
    std::fs::create_dir(&root).expect("a directory to authorise");
    let environment = fixture.environment_id();
    let params = authorise_params(environment, &root, LocationPurpose::Source, None);
    let location = authorised(fixture.service(), &owner, &params, 40);
    let original = adopt(&fixture, &root, "repo", 41);

    // The directory the owner authorised moves away, and another takes its name, holding a
    // repository of its own at the same relative name.
    std::fs::rename(&root, fixture.work().join("moved")).expect("the directory moves");
    std::fs::create_dir(&root).expect("another directory takes the name");
    let impostor = adopt(&fixture, &root, "repo", 42);

    // Before a restart the held handle still reaches the object the owner authorised, wherever
    // its name went, and never the replacement.
    attach(
        fixture.service(),
        &owner,
        original,
        location.location_id,
        43,
    )
    .expect("the authorised object is still reached through its handle");
    let refusal = attach(
        fixture.service(),
        &owner,
        impostor,
        location.location_id,
        44,
    )
    .expect_err("the replacement at the path is not beneath the held handle");
    assert_eq!(refusal.code(), ErrorCode::SourceChanged);

    // After a restart nothing is held, and nothing reaches either.
    let replacement = fixture.reopen();
    for (project, seed) in [(original, 45), (impostor, 46)] {
        let refusal = attach(&replacement, &owner, project, location.location_id, seed)
            .expect_err("a dormant location reaches nothing");
        assert_eq!(refusal.code(), ErrorCode::PermissionDenied);
    }
    // Authorising it again opens whatever holds the path now, and the challenge is bound to that
    // object: the owner confirms the replacement or nothing.
    let again = ProjectLocationAuthoriseParams {
        location_id: Nullable(Some(location.location_id)),
        ..params
    };
    let fresh = challenge_for(&replacement, &owner, &again, 47);
    let replaced_identity = kr_transfer::AuthorisedDirectory::open_root(environment, &root)
        .expect("the replacement opens")
        .identity();
    let original_identity =
        kr_transfer::AuthorisedDirectory::open_root(environment, &fixture.work().join("moved"))
            .expect("the original opens")
            .identity();
    assert_ne!(replaced_identity, original_identity);
    confirm(&replacement, &owner, &again, &fresh, 47).expect("the owner confirms the replacement");
    attach(&replacement, &owner, impostor, location.location_id, 48)
        .expect("what the owner confirmed is what the location now reaches");
}

#[test]
fn a_repository_is_bound_to_a_source_through_the_held_handle_and_released_without_confirmation() {
    let fixture = Fixture::create();
    let owner = TestOwner::default();
    let root = fixture.work().join("team");
    std::fs::create_dir_all(root.join("nested")).expect("directories");
    let environment = fixture.environment_id();
    let location = authorised(
        fixture.service(),
        &owner,
        &authorise_params(environment, &root, LocationPurpose::Source, None),
        50,
    );
    let project = adopt(&fixture, &root.join("nested"), "repo", 51);
    let bound = attach(fixture.service(), &owner, project, location.location_id, 52)
        .expect("the repository is bound");
    let LocationAttachment::Bound {
        project: summary,
        source,
    } = bound.outcome
    else {
        panic!("a confirmed binding is bound");
    };
    assert_eq!(summary.project_repository_id, project);
    let source = source.0.expect("the binding names its location");
    assert_eq!(source.location_id, location.location_id);
    assert_eq!(source.relative_path, "nested/repo");

    // Clearing the binding needs no confirmation, and a proof on it is refused as meaningless.
    let cleared = fixture
        .service()
        .project_location_attach(
            &actor(),
            &attach_params(project, None),
            Some(&submission(ATTACH, 53, false)),
            Some(&owner),
        )
        .expect("clearing a binding is answered at once");
    let LocationAttachment::Bound { source, .. } = cleared.outcome else {
        panic!("clearing a binding is not challenged");
    };
    assert!(source.0.is_none());
    let challenged = owner.issued();
    let refusal = fixture
        .service()
        .project_location_attach(
            &actor(),
            &ProjectLocationAttachParams {
                owner_confirmation: Nullable(Some(sign(&challenge_for(
                    fixture.service(),
                    &owner,
                    &authorise_params(environment, &root, LocationPurpose::Source, None),
                    54,
                )))),
                ..attach_params(project, None)
            },
            Some(&submission(ATTACH, 55, true)),
            Some(&owner),
        )
        .expect_err("a proof for clearing a binding is refused");
    assert_eq!(refusal.code(), ErrorCode::InvalidArgument);
    assert_eq!(owner.issued(), challenged + 1);
}

#[test]
fn source_outside_every_location_is_refused() {
    let fixture = Fixture::create();
    let owner = TestOwner::default();
    let environment = fixture.environment_id();
    let inside = fixture.work().join("inside");
    let outside = fixture.work().join("outside");
    std::fs::create_dir(&inside).expect("a directory");
    std::fs::create_dir(&outside).expect("a directory");
    let source = authorised(
        fixture.service(),
        &owner,
        &authorise_params(environment, &inside, LocationPurpose::Source, None),
        60,
    );
    let destination_location = authorised(
        fixture.service(),
        &owner,
        &authorise_params(environment, &inside, LocationPurpose::Destination, None),
        61,
    );
    let elsewhere = adopt(&fixture, &outside, "repo", 62);
    let refusal = attach(fixture.service(), &owner, elsewhere, source.location_id, 63)
        .expect_err("a repository outside the location is not reached through it");
    assert_eq!(refusal.code(), ErrorCode::PermissionDenied);

    // A location that is the working tree itself names nothing beneath it.
    let itself = adopt(&fixture, &inside, "own", 64);
    let own_tree = authorised(
        fixture.service(),
        &owner,
        &authorise_params(
            environment,
            &inside.join("own"),
            LocationPurpose::Source,
            None,
        ),
        65,
    );
    let refusal = attach(fixture.service(), &owner, itself, own_tree.location_id, 66)
        .expect_err("a source is authorised over the directory a repository is in");
    assert_eq!(refusal.code(), ErrorCode::PermissionDenied);

    // A destination is not a source, and an unknown location is no location.
    let refusal = attach(
        fixture.service(),
        &owner,
        itself,
        destination_location.location_id,
        67,
    )
    .expect_err("a destination does not bind a source");
    assert_eq!(refusal.code(), ErrorCode::PermissionDenied);
    let refusal = attach(
        fixture.service(),
        &owner,
        itself,
        ProjectLocationId::new(Uuid::from_bytes([0x72; 16])),
        68,
    )
    .expect_err("an unknown location binds nothing");
    assert_eq!(refusal.code(), ErrorCode::ResourceUnavailable);
    // A repository recorded through a link beneath the location is outside it, and the link is
    // not followed to find it: a name that would fabricate containment does not resolve.
    std::os::unix::fs::symlink(&outside, inside.join("link")).expect("a link out of the location");
    ordinary_repository(&outside, "reached");
    let through_link = fixture
        .service()
        .project_adopt(
            &actor(),
            &ProjectAdoptParams {
                destination: destination(environment, &inside.join("link"), "reached"),
                label: "reached".to_owned(),
                flow: AdoptionFlow::ExistingCheckout,
            },
            Some(&action("project.adopt", 69)),
        )
        .expect("the owner's own adoption resolves the path it was given")
        .project;
    assert!(
        through_link
            .display_path
            .starts_with(&inside.display().to_string()),
        "the record's path reads as though it were inside: {}",
        through_link.display_path
    );
    let refusal = attach(
        fixture.service(),
        &owner,
        through_link.project_repository_id,
        source.location_id,
        70,
    )
    .expect_err("a link beneath the location is not descended through");
    assert_eq!(refusal.code(), ErrorCode::InvalidArgument);
    assert!(
        refusal.to_string().contains("link"),
        "the refusal names the link: {refusal}"
    );
}

#[test]
fn a_binding_whose_location_is_withdrawn_after_its_challenge_is_refused_and_kept() {
    let fixture = Fixture::create();
    let owner = TestOwner::default();
    let root = fixture.work().join("racing");
    std::fs::create_dir(&root).expect("a directory");
    let environment = fixture.environment_id();
    let location = authorised(
        fixture.service(),
        &owner,
        &authorise_params(environment, &root, LocationPurpose::Source, None),
        80,
    );
    let project = adopt(&fixture, &root, "repo", 81);
    let params = attach_params(project, Some(location.location_id));
    let first = fixture
        .service()
        .project_location_attach(
            &actor(),
            &params,
            Some(&submission(ATTACH, 82, false)),
            Some(&owner),
        )
        .expect("the challenge is issued");
    let LocationAttachment::ConfirmationRequired { request } = first.outcome else {
        panic!("a binding's first submission is answered with its challenge");
    };
    fixture
        .service()
        .project_location_withdraw(
            &ProjectLocationWithdrawParams {
                location_id: location.location_id,
            },
            Some(&action(WITHDRAW, 83)),
        )
        .expect("the owner withdraws the location meanwhile");
    let proven = ProjectLocationAttachParams {
        owner_confirmation: Nullable(Some(sign(&request))),
        ..params
    };
    let refusal = fixture
        .service()
        .project_location_attach(
            &actor(),
            &proven,
            Some(&submission(ATTACH, 82, true)),
            Some(&owner),
        )
        .expect_err("the binding is checked against the policy under its lock before it commits");
    assert_eq!(refusal.code(), ErrorCode::PermissionDenied);
    // The challenge was spent, so the refusal is this action's answer from now on.
    let repeated = fixture
        .service()
        .project_location_attach(
            &actor(),
            &proven,
            Some(&submission(ATTACH, 82, true)),
            Some(&owner),
        )
        .expect_err("the kept refusal answers a repeat");
    assert_eq!(repeated.code(), ErrorCode::PermissionDenied);
    assert_eq!(repeated.to_string(), refusal.to_string());
}

#[test]
fn policy_actions_and_outbox_survive_retry_and_crash() {
    let fixture = Fixture::create();
    let owner = TestOwner::default();
    let root = fixture.work().join("journalled");
    std::fs::create_dir(&root).expect("a directory");
    let environment = fixture.environment_id();
    let params = authorise_params(environment, &root, LocationPurpose::Source, None);

    // A daemon that ends between the challenge and the proof leaves nothing behind: the challenge
    // and the handle go with it, and the proof answers nothing afterwards.
    let request = challenge_for(fixture.service(), &owner, &params, 90);
    let replacement = fixture.reopen();
    let refusal = confirm(&replacement, &owner, &params, &request, 90)
        .expect_err("a challenge does not outlive the process that issued it");
    assert_eq!(refusal.code(), ErrorCode::OwnerConfirmationRequired);
    assert!(
        replacement
            .project_location_list(&ProjectLocationListParams {
                environment_id: environment,
                grant_id: Nullable(None),
            })
            .expect("the list reads")
            .locations
            .is_empty()
    );
    drop(replacement);

    // A confirmed authorisation's retry is answered from its record, even after a restart.
    let location = authorised(fixture.service(), &owner, &params, 91);
    let retried = confirm(fixture.service(), &owner, &params, &request, 91)
        .expect("a retry of the confirmed action is answered from its record");
    assert_eq!(retried, location);
    let project = adopt(&fixture, &root, "repo", 92);
    let bound = attach(fixture.service(), &owner, project, location.location_id, 93)
        .expect("the repository is bound");
    let withdrawn = fixture
        .service()
        .project_location_withdraw(
            &ProjectLocationWithdrawParams {
                location_id: location.location_id,
            },
            Some(&action(WITHDRAW, 94)),
        )
        .expect("the location is withdrawn");
    let replacement = fixture.reopen();
    let after = confirm(&replacement, &owner, &params, &request, 91)
        .expect("the authorisation's receipt survives the restart");
    assert_eq!(
        after, location,
        "the receipt is the answer the action was given"
    );
    let rebound = replacement
        .project_location_attach(
            &actor(),
            &ProjectLocationAttachParams {
                owner_confirmation: Nullable(Some(sign(&request))),
                ..attach_params(project, Some(location.location_id))
            },
            Some(&submission(ATTACH, 93, true)),
            Some(&owner),
        )
        .expect("the binding's receipt survives the restart");
    assert_eq!(rebound, bound);
    let rewithdrawn = replacement
        .project_location_withdraw(
            &ProjectLocationWithdrawParams {
                location_id: location.location_id,
            },
            Some(&action(WITHDRAW, 94)),
        )
        .expect("the withdrawal's receipt survives the restart");
    assert_eq!(rewithdrawn, withdrawn);
    // The same identifier with the other submission's request is a different request.
    let conflict = replacement
        .project_location_authorise(
            &actor(),
            &params,
            Some(&submission(AUTHORISE, 91, false)),
            Some(&owner),
        )
        .expect_err("an answered action's identifier is not reused for another payload");
    assert_eq!(conflict.code(), ErrorCode::IdConflict);

    // Every transition was announced in the transaction that made it.
    let events = support::outbox(fixture.host());
    let subject = location.location_id.to_string();
    for kind in ["project.location.authorised", "project.location.withdrawn"] {
        assert_eq!(
            events
                .iter()
                .filter(|(event, about)| event == kind && about == &subject)
                .count(),
            1,
            "{kind} is announced once: {events:?}"
        );
    }
    assert_eq!(
        events
            .iter()
            .filter(|(event, about)| event == "project.location.attached"
                && about == &project.to_string())
            .count(),
        1,
        "the binding is announced once: {events:?}"
    );
    // A restart announces the dormancy of what was active, and a withdrawn row stays withdrawn.
    assert!(
        !events
            .iter()
            .any(|(event, about)| event == "project.location.dormant" && about == &subject),
        "a withdrawn location is not made dormant by a restart: {events:?}"
    );
    let other = fixture.work().join("other");
    std::fs::create_dir(&other).expect("a directory");
    let active = authorised(
        &replacement,
        &owner,
        &authorise_params(environment, &other, LocationPurpose::Destination, None),
        95,
    );
    drop(replacement);
    let _third = fixture.reopen();
    let events = support::outbox(fixture.host());
    assert!(
        events
            .iter()
            .any(|(event, about)| event == "project.location.dormant"
                && about == &active.location_id.to_string()),
        "the restart announced the active location's dormancy: {events:?}"
    );
}

#[test]
fn a_cleared_binding_is_an_action_whose_failure_is_kept() {
    // Clearing a binding needs no confirmation, and it is an action like any other: what it
    // answered, a failure included, is what a repeat is answered with, and its identifier is not
    // free for another request afterwards.
    let fixture = Fixture::create();
    let owner = TestOwner::default();
    let root = fixture.work().join("clearing");
    std::fs::create_dir(&root).expect("a directory");
    let project = adopt(&fixture, &root, "repo", 120);
    let unknown = ProjectRepositoryId::new(Uuid::from_bytes([0x73; 16]));
    let clear = |project| {
        fixture.service().project_location_attach(
            &actor(),
            &attach_params(project, None),
            Some(&action(ATTACH, 121)),
            Some(&owner),
        )
    };
    let refusal = clear(unknown).expect_err("an unknown repository has no binding to clear");
    assert_eq!(refusal.code(), ErrorCode::ResourceUnavailable);
    let repeated = clear(unknown).expect_err("the repeat is given the kept answer");
    assert_eq!(repeated.to_string(), refusal.to_string());
    let reused = fixture
        .service()
        .project_location_attach(
            &actor(),
            &attach_params(project, None),
            Some(&kr_project::store::Action {
                payload_digest: kr_protocol::scalars::Digest256::from_bytes([0x74; 32]),
                ..action(ATTACH, 121)
            }),
            Some(&owner),
        )
        .expect_err("the identifier is not free for another request");
    assert_eq!(reused.code(), ErrorCode::IdConflict);
}
