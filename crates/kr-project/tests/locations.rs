//! The owner's authorised locations: the policy, the held handles, the confirmation each decision
//! needs and the binding of a repository to the source it is read through.
//!
//! KR-REQ-23.42 and 23.43 (the policy half: every name this host resolves through a location
//! descends from a handle the owner authorised), KR-REQ-14.06.
//!
//! The owner's own location-bound path is here too: a clone and a workspace made through
//! locations, the withdrawal that stops each at its next admission, and the metadata discovery
//! that refuses a repository whose Git metadata would lead outside the location.
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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kr_project::ProjectService;
use kr_project::discovery::{Discovered, MAX_ALTERNATE_DEPTH, discover};
use kr_project::git::Interposition;
use kr_project::policy::{Admitting, LocationUse};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{ActionId, EnvironmentId, GrantId, ProjectLocationId, ProjectRepositoryId};
use kr_protocol::pairing::OwnerConfirmationRequest;
use kr_protocol::project::{
    AdoptionFlow, AuthorisedLocation, CloneSource, DestinationParent, DestinationRequest,
    InclusionChoice, InclusionPolicy, IsolationMechanism, LocationAttachment,
    LocationAuthorisation, LocationPurpose, LocationState, OperationState, ProjectAdoptParams,
    ProjectCloneParams, ProjectCloneResult, ProjectLocationAttachParams,
    ProjectLocationAttachResult, ProjectLocationAuthoriseParams, ProjectLocationListParams,
    ProjectLocationWithdrawParams, RemoteSpecification, RemoteTransport, RetentionPolicy,
    WorkspaceCreateParams, WorkspaceCreateResult, WorkspaceKind, WorkspaceRemoveParams,
};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{Nullable, Uuid};
use kr_transfer::{AuthorisedDirectory, RelativeName};

use support::{
    Fixture, TestOwner, action, actor, destination, git_raw, names_in, ordinary_repository, sign,
    submission,
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

/// A destination beneath a location.
fn through(
    environment_id: EnvironmentId,
    location: ProjectLocationId,
    name: &str,
) -> DestinationRequest {
    DestinationRequest {
        environment_id,
        parent: DestinationParent::Location {
            location_id: location,
        },
        name: name.to_owned(),
    }
}

/// A source beneath a location.
fn beneath(location: ProjectLocationId, relative_path: &str) -> CloneSource {
    CloneSource::Location {
        location_id: location,
        relative_path: relative_path.to_owned(),
    }
}

/// A remote at a path on this host, which only the owner names.
fn local_remote(path: &Path) -> CloneSource {
    CloneSource::Remote {
        remote: RemoteSpecification {
            remote_name: "origin".to_owned(),
            transport: RemoteTransport::LocalPath,
            url: path.display().to_string(),
            provider: String::new(),
            credential_broker: String::new(),
        },
    }
}

fn clone_into(
    service: &ProjectService,
    destination: DestinationRequest,
    source: CloneSource,
    seed: u8,
) -> Result<ProjectCloneResult, kr_project::ProjectError> {
    service.project_clone(
        &actor(),
        &ProjectCloneParams {
            destination,
            label: "cloned".to_owned(),
            source,
        },
        Some(&action("project.clone", seed)),
    )
}

/// An independent clone made through a destination, or its preview.
fn workspace_through(
    service: &ProjectService,
    project: ProjectRepositoryId,
    destination: DestinationRequest,
    preview_only: bool,
    seed: u8,
) -> Result<WorkspaceCreateResult, kr_project::ProjectError> {
    service.workspace_create(
        &actor(),
        &WorkspaceCreateParams {
            project_repository_id: project,
            label: "through a location".to_owned(),
            kind: WorkspaceKind::Isolated,
            isolation: Nullable(Some(IsolationMechanism::IndependentClone)),
            policy: InclusionPolicy {
                dirty_files: InclusionChoice::Include,
                untracked_files: InclusionChoice::Include,
                submodules: InclusionChoice::Exclude,
                binary_files: InclusionChoice::Exclude,
                generated_artefacts: InclusionChoice::Exclude,
            },
            base_revision: Nullable(None),
            base_change_set_id: Nullable(None),
            destination: Nullable(Some(destination)),
            preview_only,
        },
        Some(&action("workspace.create", seed)),
    )
}

/// Makes a directory and authorises it for the owner, for one purpose.
fn owner_location(
    fixture: &Fixture,
    owner: &TestOwner,
    root: &Path,
    purpose: LocationPurpose,
    seed: u8,
) -> ProjectLocationId {
    std::fs::create_dir_all(root).expect("a directory to authorise");
    authorised(
        fixture.service(),
        owner,
        &authorise_params(fixture.environment_id(), root, purpose, None),
        seed,
    )
    .location_id
}

fn withdraw(service: &ProjectService, location: ProjectLocationId, seed: u8) {
    service
        .project_location_withdraw(
            &ProjectLocationWithdrawParams {
                location_id: location,
            },
            Some(&action(WITHDRAW, seed)),
        )
        .expect("the owner withdraws the location");
}

/// Withdraws `location` just before the first Git child whose description starts with
/// `describe` starts, which is after that invocation's own admission, and lets the child start
/// only once the withdrawal has committed.
///
/// The withdrawal runs on another thread, as the owner's request would: the window this acts in
/// is the real one between one admission and the next.
fn withdrawing_during<R>(
    fixture: &mut Fixture,
    describe: &'static str,
    location: ProjectLocationId,
    seed: u8,
    run: impl FnOnce(&Fixture) -> R,
) -> R {
    let (ask, asked) = std::sync::mpsc::channel::<()>();
    let (done, finished) = std::sync::mpsc::channel::<()>();
    let ask = Mutex::new(ask);
    let finished = Mutex::new(finished);
    let once = AtomicBool::new(false);
    fixture.interpose(Interposition::new(Arc::new(
        move |described: &str, _: &Path, _: &Path| {
            if described.starts_with(describe) && !once.swap(true, Ordering::SeqCst) {
                let _ = ask.lock().expect("the channel").send(());
                let _ = finished
                    .lock()
                    .expect("the channel")
                    .recv_timeout(Duration::from_secs(60));
            }
        },
    )));
    let fixture = &*fixture;
    std::thread::scope(|scope| {
        scope.spawn(move || {
            if asked.recv_timeout(Duration::from_secs(60)).is_ok() {
                withdraw(fixture.service(), location, seed);
                let _ = done.send(());
            }
        });
        run(fixture)
    })
}

fn journal(fixture: &Fixture) -> rusqlite::Connection {
    rusqlite::Connection::open(
        ProjectService::root_of(&fixture.host().environment())
            .join(kr_project::store::STORE_FILE_NAME),
    )
    .expect("the journal opens")
}

/// A nullable identifier column, as the journal holds it.
type IdColumn = Option<Vec<u8>>;

/// A nullable text column.
type TextColumn = Option<String>;

fn bytes(id: Uuid) -> Vec<u8> {
    id.as_bytes().to_vec()
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
fn a_repeat_during_a_confirmation_waits_for_it_and_is_given_its_answer() {
    // The action is claimed before its challenge is spent, so a repeat that arrives in between
    // finds a claim. A claim is not an answer: the daemon's retained lookup reads nothing, and the
    // repeat goes on into the service, where it waits for the submission holding the transition
    // and is then given that submission's answer.
    let fixture = Fixture::create();
    let owner = TestOwner::default();
    let root = fixture.work().join("repeated");
    std::fs::create_dir(&root).expect("a directory");
    let params = authorise_params(
        fixture.environment_id(),
        &root,
        LocationPurpose::Source,
        None,
    );
    let request = challenge_for(fixture.service(), &owner, &params, 15);
    let proven = ProjectLocationAuthoriseParams {
        owner_confirmation: Nullable(Some(sign(&request))),
        ..params.clone()
    };
    let submitted = submission(AUTHORISE, 15, true);
    let (entered, release) = owner.hold_next_spending();
    std::thread::scope(|scope| {
        let first = scope.spawn(|| {
            fixture.service().project_location_authorise(
                &actor(),
                &proven,
                Some(&submitted),
                Some(&owner),
            )
        });
        entered
            .recv()
            .expect("the first submission has claimed its action");
        assert_eq!(
            fixture
                .service()
                .retained_action(
                    &actor(),
                    submitted.action_id,
                    &submitted.method,
                    submitted.payload_digest,
                )
                .expect("the lookup reads the journal"),
            None,
            "an open claim is not an answer, so the daemon's lookup sends a repeat on"
        );
        let repeat = scope.spawn(|| {
            fixture.service().project_location_authorise(
                &actor(),
                &proven,
                Some(&submitted),
                Some(&owner),
            )
        });
        // Long enough for the repeat to reach the transition the first submission holds. Were it
        // to arrive later, it would find the recorded answer instead, which is the same answer.
        std::thread::sleep(std::time::Duration::from_millis(200));
        release
            .send(())
            .expect("the first submission spends its challenge");
        let first = first
            .join()
            .expect("the first submission runs")
            .expect("and is authorised");
        let repeat = repeat
            .join()
            .expect("the repeat runs")
            .expect("and is given the first submission's answer");
        assert_eq!(repeat, first);
    });
}

#[test]
fn a_challenge_being_answered_keeps_its_place_in_the_bound() {
    // While one proof is being verified, its challenge is not waiting any more, and it is not
    // spent either. It keeps its place, so nothing can be issued into it, and a proof that fails
    // puts it back with the bound where it was.
    let fixture = Fixture::create();
    let owner = TestOwner::default();
    let environment = fixture.environment_id();
    let bound = kr_project::policy::MAX_OUTSTANDING_CHALLENGES;
    let mut first = None;
    for index in 0..bound {
        let directory = fixture.work().join(format!("answering-{index}"));
        std::fs::create_dir(&directory).expect("a directory");
        let params = authorise_params(environment, &directory, LocationPurpose::Source, None);
        let seed = u8::try_from(100 + index).expect("a seed");
        let request = challenge_for(fixture.service(), &owner, &params, seed);
        first.get_or_insert((params, request, seed));
    }
    let (params, request, seed) = first.expect("the first challenge");
    let beyond = fixture.work().join("beyond");
    std::fs::create_dir(&beyond).expect("a directory");
    let (entered, release) = owner.hold_next_verification();
    std::thread::scope(|scope| {
        let answering = scope.spawn(|| {
            let mut forged = sign(&request);
            forged.signature = kr_protocol::scalars::Signature64::from_bytes([0; 64]);
            fixture.service().project_location_authorise(
                &actor(),
                &ProjectLocationAuthoriseParams {
                    owner_confirmation: Nullable(Some(forged)),
                    ..params.clone()
                },
                Some(&submission(AUTHORISE, seed, true)),
                Some(&owner),
            )
        });
        entered.recv().expect("the proof is being verified");
        let refusal = fixture
            .service()
            .project_location_authorise(
                &actor(),
                &authorise_params(environment, &beyond, LocationPurpose::Source, None),
                Some(&submission(AUTHORISE, 99, false)),
                Some(&owner),
            )
            .expect_err("the challenge being answered still holds its place");
        assert_eq!(refusal.code(), ErrorCode::QuotaExceeded);
        release.send(()).expect("the verification finishes");
        let refused = answering
            .join()
            .expect("the answering thread runs")
            .expect_err("a forged proof is refused");
        assert_eq!(refused.code(), ErrorCode::OwnerConfirmationRequired);
    });
    assert_eq!(owner.outstanding(), bound, "the bound is where it was");
    // The challenge that was put back is still the owner's to answer.
    confirm(fixture.service(), &owner, &params, &request, seed)
        .expect("the owner's own proof still answers it");
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

#[test]
fn recovery_preserves_location_authority() {
    // An operation that recorded the location its destination was resolved through keeps that
    // record through a restart. Recovery reaches nothing through it, because the location is
    // dormant until the owner authorises it again, so it takes no filesystem effect, says why and
    // names the location; the row still names it for the owner's reconciliation.
    let fixture = Fixture::create();
    let owner = TestOwner::default();
    let root = fixture.work().join("destinations");
    std::fs::create_dir(&root).expect("a directory to authorise");
    let environment = fixture.environment_id();
    let location = authorised(
        fixture.service(),
        &owner,
        &authorise_params(environment, &root, LocationPurpose::Destination, None),
        40,
    );
    let source = ordinary_repository(fixture.work(), "source");
    let submitted = action("project.clone", 41);
    let cloned = fixture
        .service()
        .project_clone(
            &actor(),
            &ProjectCloneParams {
                destination: destination(environment, &root, "cloned"),
                label: "cloned".to_owned(),
                source: CloneSource::Remote {
                    remote: RemoteSpecification {
                        remote_name: "origin".to_owned(),
                        transport: RemoteTransport::LocalPath,
                        url: source.display().to_string(),
                        provider: String::new(),
                        credential_broker: String::new(),
                    },
                },
            },
            Some(&submitted),
        )
        .expect("the clone completes");
    // The state a daemon that died mid-clone through that location leaves: the row names the
    // location and the staging directory inside it, and the claim is open.
    let staging = root.join(".kr-project-through-a-location");
    support::staging_directory(&staging);
    let identity = std::fs::metadata(&staging).expect("its metadata");
    let journal = rusqlite::Connection::open(
        ProjectService::root_of(&fixture.host().environment())
            .join(kr_project::store::STORE_FILE_NAME),
    )
    .expect("the journal opens");
    journal
        .execute(
            "UPDATE operations SET state = 'staging', ended_at_ms = NULL, staged_device = NULL,
                    staged_file_id = NULL, staging_name = ?2, staging_device = ?3,
                    staging_file_id = ?4, destination_location_id = ?5
              WHERE action_id = ?1",
            rusqlite::params![
                cloned.operation.action_id.get().as_bytes().to_vec(),
                ".kr-project-through-a-location",
                std::os::unix::fs::MetadataExt::dev(&identity) as i64,
                std::os::unix::fs::MetadataExt::ino(&identity) as i64,
                location.location_id.get().as_bytes().to_vec(),
            ],
        )
        .expect("the row names its location");
    journal
        .execute(
            "UPDATE actions SET result = NULL, error_code = NULL, error_detail = NULL
              WHERE action_id = ?1",
            rusqlite::params![submitted.action_id.as_bytes().to_vec()],
        )
        .expect("the claim is open again");
    drop(journal);

    let replacement = fixture.reopen();
    let recovery = replacement.recover().expect("recovery runs");
    assert_eq!(recovery.unresolved, 1);
    assert!(
        staging.join("tree").is_dir(),
        "a dormant location reaches nothing, so nothing is removed"
    );
    let operation = replacement
        .read_operation(cloned.operation.action_id)
        .expect("the operation reads");
    assert_eq!(operation.state, OperationState::Failed);
    let detail = operation.detail.0.expect("the record says why");
    assert!(
        detail.contains(&format!("location {}", location.location_id)),
        "and names the location: {detail}"
    );
    let journal = rusqlite::Connection::open(
        ProjectService::root_of(&fixture.host().environment())
            .join(kr_project::store::STORE_FILE_NAME),
    )
    .expect("the journal opens");
    let recorded: Vec<u8> = journal
        .query_row(
            "SELECT destination_location_id FROM operations WHERE action_id = ?1",
            rusqlite::params![cloned.operation.action_id.get().as_bytes().to_vec()],
            |row| row.get(0),
        )
        .expect("the row reads");
    assert_eq!(
        recorded,
        location.location_id.get().as_bytes().to_vec(),
        "the row still names the location it recorded"
    );
}

#[test]
fn an_owner_clone_and_materialisation_succeed_through_a_location() {
    // The positive case: a location is usable, not merely safe. The owner clones a repository
    // found beneath a source location into a destination location, binds the clone to a source
    // location, makes a workspace of it through another destination location and removes it
    // again, and each step reaches its names through a handle the owner authorised.
    let fixture = Fixture::create();
    let owner = TestOwner::default();
    let environment = fixture.environment_id();
    let sources = fixture.work().join("sources");
    let projects = fixture.work().join("projects");
    let workspaces = fixture.work().join("workspaces");
    let source = owner_location(&fixture, &owner, &sources, LocationPurpose::Source, 100);
    let into = owner_location(
        &fixture,
        &owner,
        &projects,
        LocationPurpose::Destination,
        101,
    );
    let projects_as_source =
        owner_location(&fixture, &owner, &projects, LocationPurpose::Source, 102);
    let made_in = owner_location(
        &fixture,
        &owner,
        &workspaces,
        LocationPurpose::Destination,
        103,
    );
    ordinary_repository(&sources.join("team"), "upstream");

    let cloned = clone_into(
        fixture.service(),
        through(environment, into, "cloned"),
        beneath(source, "team/upstream"),
        104,
    )
    .expect("the owner clones through two locations");
    assert_eq!(cloned.operation.state, OperationState::Completed);
    assert!(projects.join("cloned/src/lib.rs").is_file());
    assert_eq!(
        cloned.project.display_path,
        projects.join("cloned").display().to_string()
    );
    let journal = journal(&fixture);
    let recorded: (IdColumn, IdColumn, IdColumn) = journal
        .query_row(
            "SELECT grant_id, destination_location_id, source_location_id FROM operations
              WHERE action_id = ?1",
            rusqlite::params![bytes(cloned.operation.action_id.get())],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("the operation's row reads");
    assert_eq!(
        recorded,
        (None, Some(bytes(into.get())), Some(bytes(source.get()))),
        "the row records the owner's authority and both locations"
    );
    let project = cloned.project.project_repository_id;
    let provenance: (IdColumn, TextColumn, IdColumn) = journal
        .query_row(
            "SELECT created_location_id, created_relative_path, source_location_id FROM projects
              WHERE project_repository_id = ?1",
            rusqlite::params![bytes(project.get())],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("the repository's row reads");
    assert_eq!(
        provenance,
        (Some(bytes(into.get())), Some("cloned".to_owned()), None),
        "creation records where it happened and binds no source"
    );

    attach(fixture.service(), &owner, project, projects_as_source, 105)
        .expect("the clone is bound to a source location");
    let made = workspace_through(
        fixture.service(),
        project,
        through(environment, made_in, "feature"),
        false,
        106,
    )
    .expect("the workspace is made through a location")
    .workspace
    .0
    .expect("a workspace, not a preview");
    assert!(workspaces.join("feature/src/lib.rs").is_file());
    let placed: (IdColumn, TextColumn) = journal
        .query_row(
            "SELECT location_id, relative_path FROM workspaces WHERE workspace_id = ?1",
            rusqlite::params![bytes(made.workspace_id.get())],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("the workspace's row reads");
    assert_eq!(
        placed,
        (Some(bytes(made_in.get())), Some("feature".to_owned()))
    );

    let removed = fixture
        .service()
        .workspace_remove(
            &WorkspaceRemoveParams {
                workspace_id: made.workspace_id,
                retention: RetentionPolicy::RemoveRetained,
            },
            Some(&action("workspace.remove", 107)),
        )
        .expect("the workspace is removed through its location");
    assert!(removed.working_files_removed);
    support::assert_absent(&workspaces.join("feature"), "the removed workspace");
}

#[test]
fn withdrawal_before_admission_refuses_prepared_operation() {
    // The source location is withdrawn while the repository beneath it is being audited, after
    // that read was admitted. The resolution completes, and the transaction that would begin the
    // operation asks the policy again and refuses: no row, no staging directory, nothing cloned.
    let mut fixture = Fixture::create();
    let owner = TestOwner::default();
    let environment = fixture.environment_id();
    let sources = fixture.work().join("sources");
    let projects = fixture.work().join("projects");
    let source = owner_location(&fixture, &owner, &sources, LocationPurpose::Source, 110);
    let into = owner_location(
        &fixture,
        &owner,
        &projects,
        LocationPurpose::Destination,
        111,
    );
    ordinary_repository(&sources, "upstream");
    let refusal = withdrawing_during(&mut fixture, "git config", source, 112, |fixture| {
        clone_into(
            fixture.service(),
            through(environment, into, "prepared"),
            beneath(source, "upstream"),
            113,
        )
    })
    .expect_err("the prepared operation does not begin");
    assert_eq!(refusal.code(), ErrorCode::PermissionDenied);
    assert!(
        refusal
            .to_string()
            .contains(&format!("location {source} is not active")),
        "{refusal}"
    );
    assert!(
        names_in(&projects).is_empty(),
        "nothing was staged: {:?}",
        names_in(&projects)
    );
    fixture
        .service()
        .read_operation(ActionId::new(action("project.clone", 113).action_id))
        .expect_err("no operation was recorded");
}

#[test]
fn an_owner_operation_after_withdrawal_does_not_begin() {
    let mut fixture = Fixture::create();
    let owner = TestOwner::default();
    let environment = fixture.environment_id();
    let sources = fixture.work().join("sources");
    let projects = fixture.work().join("projects");
    let later = fixture.work().join("later");
    let source = owner_location(&fixture, &owner, &sources, LocationPurpose::Source, 120);
    let into = owner_location(
        &fixture,
        &owner,
        &projects,
        LocationPurpose::Destination,
        121,
    );
    let then = owner_location(&fixture, &owner, &later, LocationPurpose::Destination, 122);
    ordinary_repository(&sources, "upstream");

    // At a read: the destination location goes while the clone runs, after that invocation's
    // admission. The next invocation is refused, and the staging directory the operation made
    // there is kept and named with the reason rather than removed through a location that no
    // longer admits it.
    let refusal = withdrawing_during(&mut fixture, "git clone", into, 123, |fixture| {
        clone_into(
            fixture.service(),
            through(environment, into, "interrupted"),
            beneath(source, "upstream"),
            124,
        )
    })
    .expect_err("the read after the withdrawal is refused");
    assert_eq!(refusal.code(), ErrorCode::PermissionDenied, "{refusal}");
    let operation = fixture
        .service()
        .read_operation(ActionId::new(action("project.clone", 124).action_id))
        .expect("the operation reads");
    assert_eq!(operation.state, OperationState::Failed);
    let kept = names_in(&projects);
    assert_eq!(kept.len(), 1, "the staging directory is kept: {kept:?}");
    let detail = operation.detail.0.expect("the record says why");
    assert!(
        detail.contains(&projects.join(&kept[0]).display().to_string()),
        "{detail}"
    );
    assert!(
        detail.contains(&format!("location {into} is not active")),
        "{detail}"
    );

    // At the resolution: an operation through the withdrawn location is refused before anything.
    let refusal = clone_into(
        fixture.service(),
        through(environment, into, "after"),
        beneath(source, "upstream"),
        125,
    )
    .expect_err("a withdrawn location resolves nothing");
    assert_eq!(refusal.code(), ErrorCode::PermissionDenied);
    assert_eq!(names_in(&projects), kept);

    // And through a location that is still active, the same operation completes.
    clone_into(
        fixture.service(),
        through(environment, then, "after"),
        beneath(source, "upstream"),
        126,
    )
    .expect("an active location still reaches");
}

#[test]
fn preview_after_withdrawal_does_not_begin() {
    // A preview returns without the transaction that begins an effect, so it is admitted as a
    // read: once a location it reaches through is withdrawn, neither the preview nor the creation
    // it prepared begins, and nothing is created.
    let fixture = Fixture::create();
    let owner = TestOwner::default();
    let environment = fixture.environment_id();
    let sources = fixture.work().join("sources");
    let workspaces = fixture.work().join("workspaces");
    let elsewhere = fixture.work().join("elsewhere");
    let source = owner_location(&fixture, &owner, &sources, LocationPurpose::Source, 130);
    let made_in = owner_location(
        &fixture,
        &owner,
        &workspaces,
        LocationPurpose::Destination,
        131,
    );
    let other = owner_location(
        &fixture,
        &owner,
        &elsewhere,
        LocationPurpose::Destination,
        132,
    );
    let project = adopt(&fixture, &sources, "repo", 133);
    attach(fixture.service(), &owner, project, source, 134).expect("the repository is bound");

    let previewed = workspace_through(
        fixture.service(),
        project,
        through(environment, made_in, "ws"),
        true,
        135,
    )
    .expect("the preview is taken");
    assert!(previewed.workspace.0.is_none());
    withdraw(fixture.service(), made_in, 136);
    for (seed, preview_only) in [(137, true), (138, false)] {
        let refusal = workspace_through(
            fixture.service(),
            project,
            through(environment, made_in, "ws"),
            preview_only,
            seed,
        )
        .expect_err("a withdrawn destination begins nothing");
        assert_eq!(refusal.code(), ErrorCode::PermissionDenied);
    }
    assert!(names_in(&workspaces).is_empty());

    // The source location's withdrawal refuses a preview through another destination too.
    workspace_through(
        fixture.service(),
        project,
        through(environment, other, "ws"),
        true,
        139,
    )
    .expect("the other destination previews");
    withdraw(fixture.service(), source, 140);
    let refusal = workspace_through(
        fixture.service(),
        project,
        through(environment, other, "ws"),
        true,
        141,
    )
    .expect_err("the repository is read through nothing now");
    assert_eq!(refusal.code(), ErrorCode::PermissionDenied);
    assert!(names_in(&elsewhere).is_empty());
}

#[test]
fn the_three_metadata_refusals_apply_to_an_owner_location() {
    // A worktree backlink, a core.worktree and a submodule each refuse a repository to the
    // owner's own location, before anything is created: the owner reaches such a repository by
    // naming its path, never through a location.
    let fixture = Fixture::create();
    let owner = TestOwner::default();
    let environment = fixture.environment_id();
    let sources = fixture.work().join("sources");
    let projects = fixture.work().join("projects");
    let source = owner_location(&fixture, &owner, &sources, LocationPurpose::Source, 150);
    let into = owner_location(
        &fixture,
        &owner,
        &projects,
        LocationPurpose::Destination,
        151,
    );
    let linked = ordinary_repository(&sources, "linked");
    git_raw(&linked, ["worktree", "add", "--quiet", "../linked-tree"]);
    let configured = ordinary_repository(&sources, "configured");
    git_raw(
        &configured,
        [
            "config",
            "core.worktree",
            configured.to_str().expect("a path in text"),
        ],
    );
    let child = ordinary_repository(fixture.work(), "child");
    let with_submodule = ordinary_repository(&sources, "with-submodule");
    git_raw(
        &with_submodule,
        [
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            "--quiet",
            child.to_str().expect("a path in text"),
            "child",
        ],
    );
    for (seed, relative, named) in [
        (152, "linked", "worktree"),
        (153, "linked-tree", ".git"),
        (154, "configured", "core.worktree"),
        (155, "with-submodule", "submodule"),
    ] {
        let refusal = clone_into(
            fixture.service(),
            through(environment, into, relative),
            beneath(source, relative),
            seed,
        )
        .expect_err("the repository is refused to the location");
        assert_eq!(
            refusal.code(),
            ErrorCode::PermissionDenied,
            "{relative}: {refusal}"
        );
        assert!(refusal.to_string().contains(named), "{relative}: {refusal}");
    }
    assert!(
        names_in(&projects).is_empty(),
        "nothing was created: {:?}",
        names_in(&projects)
    );
}

#[test]
fn destination_name_cannot_escape() {
    // Through a location, a destination is one entry in the directory the location's handle
    // holds. A separator, a traversal segment, an absolute name and an empty one are refused
    // before anything is created, and a link already at the name is neither followed nor
    // replaced, by a creation or by an adoption.
    let fixture = Fixture::create();
    let owner = TestOwner::default();
    let environment = fixture.environment_id();
    let projects = fixture.work().join("projects");
    let into = owner_location(
        &fixture,
        &owner,
        &projects,
        LocationPurpose::Destination,
        160,
    );
    let upstream = ordinary_repository(fixture.work(), "upstream");
    let outside = ordinary_repository(fixture.work(), "outside");
    let outside_before = names_in(&outside);
    let before = names_in(fixture.work());
    for (seed, name) in [
        (161, ".."),
        (162, "."),
        (163, ""),
        (164, "nested/name"),
        (165, "../outside"),
        (166, "/absolute"),
    ] {
        clone_into(
            fixture.service(),
            through(environment, into, name),
            local_remote(&upstream),
            seed,
        )
        .expect_err("the name is not one entry beneath the location");
    }
    assert!(names_in(&projects).is_empty());
    std::os::unix::fs::symlink(&outside, projects.join("linked")).expect("a link at the name");
    clone_into(
        fixture.service(),
        through(environment, into, "linked"),
        local_remote(&upstream),
        167,
    )
    .expect_err("a taken name is not created over");
    fixture
        .service()
        .project_adopt(
            &actor(),
            &ProjectAdoptParams {
                destination: through(environment, into, "linked"),
                label: "linked".to_owned(),
                flow: AdoptionFlow::ExistingCheckout,
            },
            Some(&action("project.adopt", 168)),
        )
        .expect_err("a link at the name is not adopted through");
    assert_eq!(
        names_in(&outside),
        outside_before,
        "nothing went through the link"
    );
    assert_eq!(names_in(&projects), vec!["linked".to_owned()]);
    assert!(
        std::fs::symlink_metadata(projects.join("linked"))
            .expect("the link")
            .file_type()
            .is_symlink()
    );
    assert_eq!(names_in(fixture.work()), before);
}

#[test]
fn destination_symlink_and_replacement_races_do_not_redirect() {
    let mut fixture = Fixture::create();
    let owner = TestOwner::default();
    let environment = fixture.environment_id();
    let projects = fixture.work().join("projects");
    let moved = fixture.work().join("moved");
    let elsewhere = fixture.work().join("elsewhere");
    let into = owner_location(
        &fixture,
        &owner,
        &projects,
        LocationPurpose::Destination,
        170,
    );
    let upstream = ordinary_repository(fixture.work(), "upstream");

    // A link put at the name while the clone runs is not published over, and nothing goes
    // through it.
    std::fs::create_dir(&elsewhere).expect("somewhere else");
    let racing = projects.join("raced");
    let target = elsewhere.clone();
    let once = AtomicBool::new(false);
    fixture.interpose(Interposition::new(Arc::new(
        move |described: &str, _: &Path, _: &Path| {
            if described.starts_with("git clone") && !once.swap(true, Ordering::SeqCst) {
                std::os::unix::fs::symlink(&target, &racing).expect("a link at the name");
            }
        },
    )));
    clone_into(
        fixture.service(),
        through(environment, into, "raced"),
        local_remote(&upstream),
        171,
    )
    .expect_err("the publication does not replace what took the name");
    assert!(
        names_in(&elsewhere).is_empty(),
        "nothing went through the link"
    );
    assert!(
        std::fs::symlink_metadata(projects.join("raced"))
            .expect("the name")
            .file_type()
            .is_symlink()
    );
    let after_the_race = names_in(&projects);

    // The location's directory is moved after it was authorised and a link to somewhere else put
    // at its path. The held handle is still the directory the owner authorised, and nothing is
    // written through the link: Git is given the staging directory by path, and the invocation
    // requires the object there to be the one this host created, so it does not run elsewhere.
    std::fs::rename(&projects, &moved).expect("the location's directory is moved");
    std::os::unix::fs::symlink(&elsewhere, &projects).expect("a link at the location's path");
    clone_into(
        fixture.service(),
        through(environment, into, "landed"),
        local_remote(&upstream),
        172,
    )
    .expect_err("the directory Git would be given is not the one this host made");
    assert!(
        names_in(&elsewhere).is_empty(),
        "nothing went through the link"
    );
    assert_eq!(
        names_in(&moved),
        after_the_race,
        "and the staging directory made through the handle is gone again"
    );
}

#[test]
fn a_repository_created_through_a_destination_needs_an_attached_source() {
    // Where a repository was created is recorded, and it is not source authority: a clone of it by
    // registration and a workspace of it made through a location are refused until the owner
    // binds it to a source location, and succeed once the owner has.
    let fixture = Fixture::create();
    let owner = TestOwner::default();
    let environment = fixture.environment_id();
    let projects = fixture.work().join("projects");
    let workspaces = fixture.work().join("workspaces");
    let into = owner_location(
        &fixture,
        &owner,
        &projects,
        LocationPurpose::Destination,
        180,
    );
    let made_in = owner_location(
        &fixture,
        &owner,
        &workspaces,
        LocationPurpose::Destination,
        181,
    );
    let upstream = ordinary_repository(fixture.work(), "upstream");
    let project = clone_into(
        fixture.service(),
        through(environment, into, "made"),
        local_remote(&upstream),
        182,
    )
    .expect("the owner clones into a destination location")
    .project
    .project_repository_id;
    let registered = CloneSource::Registered {
        project_repository_id: project,
    };
    let refusal = clone_into(
        fixture.service(),
        through(environment, into, "copy"),
        registered.clone(),
        183,
    )
    .expect_err("a repository bound to no source is reached through nothing");
    assert_eq!(refusal.code(), ErrorCode::PermissionDenied);
    let refusal = workspace_through(
        fixture.service(),
        project,
        through(environment, made_in, "ws"),
        false,
        184,
    )
    .expect_err("nor is a workspace of it made through a location");
    assert_eq!(refusal.code(), ErrorCode::PermissionDenied);
    assert_eq!(names_in(&projects), vec!["made".to_owned()]);
    assert!(names_in(&workspaces).is_empty());

    let source = owner_location(&fixture, &owner, &projects, LocationPurpose::Source, 185);
    attach(fixture.service(), &owner, project, source, 186).expect("the owner binds it");
    clone_into(
        fixture.service(),
        through(environment, into, "copy"),
        registered,
        187,
    )
    .expect("a bound repository is cloned by registration");
    assert!(projects.join("copy/README.md").is_file());
    workspace_through(
        fixture.service(),
        project,
        through(environment, made_in, "ws"),
        false,
        188,
    )
    .expect("and a workspace of it is made through a location");
    assert!(workspaces.join("ws/README.md").is_file());
}

#[test]
fn attaching_a_different_source_root_keeps_creation_provenance() {
    // A repository created through `srv/projects` records `repo` there, and a later binding
    // through `srv` records `projects/repo`: each pair keeps its own relative path.
    let fixture = Fixture::create();
    let owner = TestOwner::default();
    let environment = fixture.environment_id();
    let srv = fixture.work().join("srv");
    let projects = srv.join("projects");
    let into = owner_location(
        &fixture,
        &owner,
        &projects,
        LocationPurpose::Destination,
        190,
    );
    let above = owner_location(&fixture, &owner, &srv, LocationPurpose::Source, 191);
    let upstream = ordinary_repository(fixture.work(), "upstream");
    let project = clone_into(
        fixture.service(),
        through(environment, into, "repo"),
        local_remote(&upstream),
        192,
    )
    .expect("the clone")
    .project
    .project_repository_id;
    let bound = attach(fixture.service(), &owner, project, above, 193)
        .expect("bound through the directory above");
    let LocationAttachment::Bound { source, .. } = bound.outcome else {
        panic!("a confirmed binding is bound");
    };
    let source = source.0.expect("the binding names its location");
    assert_eq!(source.location_id, above);
    assert_eq!(source.relative_path, "projects/repo");
    let pairs: (IdColumn, TextColumn, IdColumn, TextColumn) = journal(&fixture)
        .query_row(
            "SELECT created_location_id, created_relative_path, source_location_id,
                    source_relative_path
               FROM projects WHERE project_repository_id = ?1",
            rusqlite::params![bytes(project.get())],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .expect("the repository's row reads");
    assert_eq!(
        pairs,
        (
            Some(bytes(into.get())),
            Some("repo".to_owned()),
            Some(bytes(above.get())),
            Some("projects/repo".to_owned())
        )
    );
}

#[test]
fn source_parent_rename_cannot_fabricate_containment() {
    // A source S in a parent P beneath a location's root R. The binding names S's object: once P
    // is moved out of R and another repository put where S was, a read by registration is refused
    // rather than given the impostor. And a repository recorded outside R and then moved inside it
    // is not bound through R: the record, not where the object is now, says where it was.
    let fixture = Fixture::create();
    let owner = TestOwner::default();
    let environment = fixture.environment_id();
    let root = fixture.work().join("root");
    let projects = fixture.work().join("projects");
    let source = owner_location(&fixture, &owner, &root, LocationPurpose::Source, 200);
    let into = owner_location(
        &fixture,
        &owner,
        &projects,
        LocationPurpose::Destination,
        201,
    );
    let project = adopt(&fixture, &root.join("team"), "repo", 202);
    attach(fixture.service(), &owner, project, source, 203).expect("bound");
    std::fs::rename(root.join("team"), fixture.work().join("away")).expect("P leaves R");
    ordinary_repository(&root.join("team"), "repo");
    let refusal = clone_into(
        fixture.service(),
        through(environment, into, "copy"),
        CloneSource::Registered {
            project_repository_id: project,
        },
        204,
    )
    .expect_err("the impostor is not the bound repository");
    assert_eq!(refusal.code(), ErrorCode::SourceChanged, "{refusal}");
    assert!(names_in(&projects).is_empty());

    let outside = fixture.work().join("outside");
    let moved_in = adopt(&fixture, &outside.join("p"), "repo", 205);
    std::fs::rename(outside.join("p"), root.join("p")).expect("the parent moves into R");
    let refusal = attach(fixture.service(), &owner, moved_in, source, 206)
        .expect_err("the record says it is outside");
    assert_eq!(refusal.code(), ErrorCode::PermissionDenied, "{refusal}");
}

// ----- metadata discovery through a location's handle -----------------------------------------

fn held_root(root: &Path) -> AuthorisedDirectory {
    AuthorisedDirectory::open_root(EnvironmentId::new(Uuid::from_bytes([6; 16])), root)
        .and_then(AuthorisedDirectory::confined_to_one_mount)
        .expect("the location opens, confined to its mount")
}

/// Lays out the directories Git would make, without running Git: this is about names.
fn laid_out(root: &Path, name: &str) -> std::path::PathBuf {
    let tree = root.join(name);
    std::fs::create_dir_all(tree.join(".git/objects/info")).expect("a Git directory");
    std::fs::create_dir_all(tree.join(".git/info")).expect("its info directory");
    tree
}

fn discovered_at(root: &Path, name: &str) -> kr_project::Result<Discovered> {
    let tree = held_root(root)
        .subdirectory(&relative(name))
        .expect("the tree opens");
    discover(tree, name)
}

fn relative(text: &str) -> RelativeName {
    RelativeName::parse(text).expect("a relative name")
}

fn refusal_of(outcome: kr_project::Result<Discovered>) -> String {
    match outcome {
        Ok(_) => panic!("the repository is refused to the location"),
        Err(error) => error.to_string(),
    }
}

#[test]
fn metadata_bases_are_git_s_own() {
    // A `.git` directory is the Git directory; a `.git` file names one relative to the working
    // tree that holds it; `commondir` is relative to the Git directory; the objects are the
    // common directory's.
    let root = tempfile::tempdir().expect("a directory");
    laid_out(root.path(), "plain");
    let plain = discovered_at(root.path(), "plain").expect("an ordinary repository is found");
    assert_eq!(plain.git_dir.identity(), plain.common_dir.identity());
    assert_eq!(plain.objects.len(), 1);

    std::fs::create_dir_all(root.path().join("filed/meta/objects")).expect("a Git directory");
    std::fs::write(root.path().join("filed/.git"), b"gitdir: meta\n").expect("a .git file");
    let filed =
        discovered_at(root.path(), "filed").expect("a .git file naming a directory beneath");
    assert_eq!(
        filed.git_dir.identity(),
        held_root(root.path())
            .subdirectory(&relative("filed/meta"))
            .expect("it opens")
            .identity(),
        "the value is relative to the working tree"
    );

    // An absolute value and one that climbs are both refused, naming the file.
    std::fs::write(
        root.path().join("filed/.git"),
        format!("gitdir: {}\n", root.path().join("filed/meta").display()),
    )
    .expect("an absolute .git file");
    let refused = refusal_of(discovered_at(root.path(), "filed"));
    assert!(refused.contains(".git"), "{refused}");
    std::fs::write(root.path().join("filed/.git"), b"gitdir: ../elsewhere\n")
        .expect("a .git file that climbs");
    let refused = refusal_of(discovered_at(root.path(), "filed"));
    assert!(refused.contains(".git"), "{refused}");
}

#[test]
fn a_downward_commondir_uses_the_common_object_directory() {
    // With a `commondir`, the object directory is the common directory's, not the Git
    // directory's: reading alternates from the wrong one would resolve them against the wrong
    // base.
    let root = tempfile::tempdir().expect("a directory");
    let tree = root.path().join("split");
    std::fs::create_dir_all(tree.join(".git/shared/objects/info")).expect("a common directory");
    std::fs::create_dir_all(tree.join(".git/objects/info")).expect("a decoy object directory");
    std::fs::write(tree.join(".git/commondir"), b"shared\n").expect("a commondir");
    std::fs::write(tree.join(".git/objects/info/alternates"), b"/etc\n")
        .expect("alternates in the directory Git does not read");
    let split = discovered_at(root.path(), "split").expect("the common directory is beneath");
    assert_eq!(
        split.objects[0].identity(),
        held_root(root.path())
            .subdirectory(&relative("split/.git/shared/objects"))
            .expect("it opens")
            .identity(),
        "the object directory is the common directory's"
    );
    std::fs::write(tree.join(".git/commondir"), b"../..\n").expect("a climbing commondir");
    let refused = refusal_of(discovered_at(root.path(), "split"));
    assert!(refused.contains("commondir"), "{refused}");
}

#[test]
fn recursive_alternates_are_bounded_and_acyclic() {
    let root = tempfile::tempdir().expect("a directory");
    let tree = laid_out(root.path(), "alternated");
    let objects = tree.join(".git/objects");
    // A chain, each resolved from the object directory that names it.
    std::fs::create_dir_all(objects.join("one/info")).expect("an alternate");
    std::fs::create_dir_all(objects.join("one/two/info")).expect("its alternate");
    std::fs::write(
        objects.join("info/alternates"),
        b"# a comment Git skips\none\n",
    )
    .expect("the first link");
    std::fs::write(objects.join("one/info/alternates"), b"two\n").expect("the second link");
    let chained = discovered_at(root.path(), "alternated").expect("a chain beneath is followed");
    assert_eq!(chained.objects.len(), 3);

    // A loop is refused rather than gone round.
    std::fs::write(objects.join("one/two/info/alternates"), b"../..\n").expect("a link back up");
    let refused = refusal_of(discovered_at(root.path(), "alternated"));
    assert!(refused.contains("alternates"), "{refused}");
    std::fs::remove_file(objects.join("one/two/info/alternates")).expect("unlinked");

    // A chain past the bound is refused.
    let mut here = objects.join("one/two");
    for step in 0..MAX_ALTERNATE_DEPTH {
        let next = format!("d{step}");
        std::fs::create_dir_all(here.join(&next).join("info")).expect("a deeper alternate");
        std::fs::write(here.join("info/alternates"), format!("{next}\n")).expect("a deeper link");
        here = here.join(next);
    }
    let refused = refusal_of(discovered_at(root.path(), "alternated"));
    assert!(refused.contains("deep"), "{refused}");
}

#[test]
fn an_ordinary_linked_worktree_is_refused_through_a_location() {
    // A linked worktree's `.git` file names an absolute Git directory, and its repository carries
    // the backlink: neither is something a location reaches.
    let root = tempfile::tempdir().expect("a directory");
    let main = laid_out(root.path(), "main");
    std::fs::create_dir_all(main.join(".git/worktrees/linked")).expect("a backlink");
    std::fs::write(main.join(".git/worktrees/linked/gitdir"), b"linked/.git\n")
        .expect("a relative backlink, which a name check alone would pass");
    let refused = refusal_of(discovered_at(root.path(), "main"));
    assert!(refused.contains("worktree"), "{refused}");
    std::fs::create_dir(root.path().join("linked")).expect("the linked tree");
    std::fs::write(
        root.path().join("linked/.git"),
        format!("gitdir: {}\n", main.join(".git/worktrees/linked").display()),
    )
    .expect("its .git file");
    let refused = refusal_of(discovered_at(root.path(), "linked"));
    assert!(refused.contains(".git"), "{refused}");
}

#[test]
fn common_pattern_files_and_per_worktree_sparse_checkout_are_distinguished() {
    // `info/exclude` and `info/attributes` belong to the common directory and
    // `info/sparse-checkout` to the per-worktree one; each has to be a file beneath its own base,
    // and a link at any of them refuses the repository.
    let root = tempfile::tempdir().expect("a directory");
    let tree = root.path().join("patterned");
    std::fs::create_dir_all(tree.join(".git/shared/objects")).expect("a common directory");
    std::fs::create_dir_all(tree.join(".git/shared/info")).expect("its info");
    std::fs::create_dir_all(tree.join(".git/info")).expect("the per-worktree info");
    std::fs::write(tree.join(".git/commondir"), b"shared\n").expect("a commondir");
    std::fs::write(tree.join(".git/shared/info/exclude"), b"*.o\n").expect("patterns");
    std::fs::write(tree.join(".git/info/sparse-checkout"), b"/src/\n").expect("patterns");
    discovered_at(root.path(), "patterned").expect("pattern files beneath their own bases");

    let outside = root.path().join("outside");
    std::fs::write(&outside, b"*\n").expect("a file outside");
    std::os::unix::fs::symlink(&outside, tree.join(".git/shared/info/attributes"))
        .expect("a common pattern file that is a link");
    let refused = refusal_of(discovered_at(root.path(), "patterned"));
    assert!(refused.contains("info/attributes"), "{refused}");
    std::fs::remove_file(tree.join(".git/shared/info/attributes")).expect("unlinked");
    std::fs::remove_file(tree.join(".git/info/sparse-checkout")).expect("unlinked");
    std::os::unix::fs::symlink(&outside, tree.join(".git/info/sparse-checkout"))
        .expect("a per-worktree pattern file that is a link");
    let refused = refusal_of(discovered_at(root.path(), "patterned"));
    assert!(refused.contains("info/sparse-checkout"), "{refused}");
}

#[test]
fn discovery_reads_nothing_the_location_does_not_authorise() {
    // An alternate outside the location, an alternate that is a link, a `.git` that is a link, a
    // submodule and a network alternate each refuse the repository before anything is read from
    // where they point.
    let root = tempfile::tempdir().expect("a directory");
    let elsewhere = tempfile::tempdir().expect("somewhere the location does not reach");
    let tree = laid_out(root.path(), "reaching");
    let objects = tree.join(".git/objects");
    std::fs::write(
        objects.join("info/alternates"),
        format!("{}\n", elsewhere.path().display()),
    )
    .expect("an absolute alternate");
    assert!(refusal_of(discovered_at(root.path(), "reaching")).contains("alternates"));
    std::fs::remove_file(objects.join("info/alternates")).expect("unlinked");

    std::os::unix::fs::symlink(elsewhere.path(), objects.join("outward"))
        .expect("a link inside the object directory");
    std::fs::write(objects.join("info/alternates"), b"outward\n").expect("naming the link");
    assert!(refusal_of(discovered_at(root.path(), "reaching")).contains("link"));
    std::fs::remove_file(objects.join("info/alternates")).expect("unlinked");

    std::fs::write(
        objects.join("info/http-alternates"),
        b"https://example.invalid\n",
    )
    .expect("a network alternate");
    assert!(refusal_of(discovered_at(root.path(), "reaching")).contains("network"));
    std::fs::remove_file(objects.join("info/http-alternates")).expect("unlinked");

    std::fs::write(tree.join(".gitmodules"), b"[submodule \"x\"]\n").expect("a submodule");
    assert!(refusal_of(discovered_at(root.path(), "reaching")).contains("submodule"));
    std::fs::remove_file(tree.join(".gitmodules")).expect("unlinked");

    std::fs::create_dir(root.path().join("linked-git")).expect("a tree");
    std::os::unix::fs::symlink(tree.join(".git"), root.path().join("linked-git/.git"))
        .expect("a .git that is a link");
    assert!(refusal_of(discovered_at(root.path(), "linked-git")).contains("link"));

    discovered_at(root.path(), "reaching").expect("and with all of that gone, it is found");
}
