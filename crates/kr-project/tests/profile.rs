//! The restricted Git execution profile, against repositories that try to escape it.
//!
//! Every test here builds a real repository with installed Git, plants every execution-capable
//! thing `fixtures/project/restricted-profile.json` names, and then asks the project service to do
//! the things that would trigger them: a status, a review refresh, a clone and an adoption. A
//! sentinel file means a helper ran, and no sentinel may exist.
//!
//! KR-ACC-030, KR-REQ-14.23 and KR-REQ-14.24.

#![cfg(feature = "git-fixtures")]

mod support;

use std::ffi::OsStr;

use kr_project::git::{ConfigurationAudit, GitRequest, check_arguments};
use kr_project::identity::OpenedRepository;
use kr_project::workspace::{PreviewRequest, survey};
use kr_protocol::project::{AdoptionFlow, ProjectAdoptParams, WorkspaceKind};

use support::{
    Fixture, action, actor, destination, include_everything, installed_broker, ordinary_repository,
    planted_repository, restricted_profile_fixture, write,
};

#[test]
fn no_planted_helper_runs_during_a_status_or_a_review_refresh() {
    let fixture = Fixture::create();
    let planted = planted_repository(fixture.work(), "planted", false);
    // Something for a filter and a textconv to be invoked on: a tracked file with an uncommitted
    // change, an untracked file and an ignored one.
    write(&planted.path, "README.md", "changed after the commit\n");
    write(&planted.path, "new.txt", "untracked\n");
    write(&planted.path, ".gitignore", "generated/\n");
    write(&planted.path, "generated/output.txt", "a build product\n");

    let repository = OpenedRepository::open(
        fixture.service().profile(),
        fixture.environment_id(),
        &planted.path,
    )
    .expect("a planted repository still opens: its helpers are neutralised, not fatal");

    // The status a reviewer's inclusion preview is taken from. A clean or a process filter would
    // run here, and an fsmonitor hook would run here.
    let surveyed = survey(
        fixture.service().profile(),
        &repository,
        &PreviewRequest {
            project_repository_id: kr_protocol::ids::ProjectRepositoryId::new(
                kr_protocol::scalars::Uuid::from_bytes([1; 16]),
            ),
            kind: WorkspaceKind::Isolated,
            policy: include_everything(),
            base_revision: "HEAD",
            base_reference: None,
            base_change_set_id: None,
            at_ms: kr_protocol::scalars::TimestampMs::new(1),
        },
    )
    .expect("the status is read");
    assert!(
        !surveyed.entries.is_empty(),
        "the status found the changes this test made"
    );

    // The review refresh: a diff of the working tree against HEAD. An external diff program and a
    // textconv driver would both run here.
    let arguments: [&OsStr; 5] = [
        OsStr::new("diff"),
        OsStr::new("--no-ext-diff"),
        OsStr::new("--no-textconv"),
        OsStr::new("--name-only"),
        OsStr::new("HEAD"),
    ];
    fixture
        .service()
        .profile()
        .run_checked(&repository.read(&arguments))
        .expect("the review refresh is read");

    assert_eq!(
        planted.escaped(),
        Vec::<String>::new(),
        "no planted helper ran during the status or the review refresh"
    );
}

#[test]
fn no_planted_helper_runs_during_a_clone_of_the_planted_repository_or_an_adoption_of_it() {
    let fixture = Fixture::with_brokers(installed_broker());
    let planted = planted_repository(fixture.work(), "source", false);

    // A local-path clone of the planted repository. An `uploadpack.packObjectsHook` and every
    // template and checkout hook would run here.
    let cloned = fixture
        .service()
        .project_clone(
            &actor(),
            &kr_protocol::project::ProjectCloneParams {
                destination: destination(fixture.environment_id(), fixture.work(), "cloned"),
                label: "cloned".to_owned(),
                remote: kr_protocol::project::RemoteSpecification {
                    remote_name: "origin".to_owned(),
                    transport: kr_protocol::project::RemoteTransport::LocalPath,
                    url: planted.path.display().to_string(),
                    provider: String::new(),
                    credential_broker: String::new(),
                },
            },
            Some(&action("project.clone", 2)),
        )
        .expect("a planted repository can still be cloned");
    assert_eq!(
        cloned.operation.state,
        kr_protocol::project::OperationState::Completed
    );

    // And an adoption of the planted repository itself, which reads its configuration.
    let adopted = fixture
        .service()
        .project_adopt(
            &actor(),
            &ProjectAdoptParams {
                destination: destination(fixture.environment_id(), fixture.work(), "source"),
                label: "adopted".to_owned(),
                flow: AdoptionFlow::ExistingCheckout,
            },
            Some(&action("project.adopt", 3)),
        )
        .expect("an existing checkout is adopted");
    assert_eq!(adopted.project.label, "adopted");

    assert_eq!(
        planted.escaped(),
        Vec::<String>::new(),
        "no planted helper ran during the clone or the adoption"
    );

    // A clone copies the template's hooks into the new repository, so the new one has none.
    let hooks = fixture.work().join("cloned/.git/hooks");
    let installed: Vec<String> = std::fs::read_dir(&hooks)
        .map(|entries| {
            entries
                .filter_map(|entry| {
                    entry
                        .ok()
                        .map(|entry| entry.file_name().to_string_lossy().into_owned())
                })
                .filter(|name| !name.ends_with(".sample"))
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(
        installed,
        Vec::<String>::new(),
        "the clone copied no hook out of the planted template"
    );
}

#[test]
fn a_repository_whose_configuration_names_a_remote_helper_is_refused_rather_than_adopted() {
    let fixture = Fixture::create();
    let planted = planted_repository(fixture.work(), "refusing", true);
    // Reading it is allowed and the limitation is exposed, which is what section 14 asks for in
    // place of executing an ungranted helper.
    let repository = OpenedRepository::open(
        fixture.service().profile(),
        fixture.environment_id(),
        &planted.path,
    )
    .expect("a read exposes the limitation rather than refusing");
    let limitations = repository.audit().limitations().join("\n");
    for key in ["remote.origin.vcs", "insteadof"] {
        assert!(
            limitations.contains(key),
            "the limitation names {key}: {limitations}"
        );
    }
    assert_eq!(
        repository.audit().refused,
        vec![
            "remote.origin.vcs",
            "url.https://example.invalid/.insteadof"
        ]
    );
    // Taking it into this host's registry is refused: a record is a promise to serve the
    // repository and its remotes, and this host cannot neutralise what that configuration names.
    let refusal = fixture
        .service()
        .project_adopt(
            &actor(),
            &ProjectAdoptParams {
                destination: destination(fixture.environment_id(), fixture.work(), "refusing"),
                label: "refusing".to_owned(),
                flow: AdoptionFlow::ExistingCheckout,
            },
            Some(&action("project.adopt", 4)),
        )
        .expect_err("the adoption is refused");
    assert_eq!(
        refusal.code(),
        kr_protocol::error::ErrorCode::RepositoryUntrusted
    );
    for key in ["remote.origin.vcs", "insteadof"] {
        assert!(
            refusal.to_string().contains(key),
            "the refusal names {key}: {refusal}"
        );
    }
    assert_eq!(
        planted.escaped(),
        Vec::<String>::new(),
        "nothing ran before the refusal"
    );
}

#[test]
fn every_neutralised_key_the_fixture_names_is_exposed_as_a_limitation() {
    // Section 14 says that where faithful interpretation requires an ungranted helper, the host
    // exposes the limitation instead of executing it. So every key the fixture plants has to
    // appear in what the host says about the repository.
    let fixture = Fixture::create();
    let planted = planted_repository(fixture.work(), "audited", false);
    let repository = OpenedRepository::open(
        fixture.service().profile(),
        fixture.environment_id(),
        &planted.path,
    )
    .expect("the repository opens");
    let limitations = repository.audit().limitations().join("\n").to_lowercase();
    for key in &planted.neutralised {
        let key = key.to_lowercase();
        // A driver key is neutralised by its driver rather than by its own name, and the
        // limitation says so: "the filter driver marker is defined and is not run".
        let stated = key.split('.').collect::<Vec<&str>>();
        let by_driver = stated.len() == 3
            && limitations.contains(&format!("{} driver {}", stated[0], stated[1]));
        assert!(
            limitations.contains(&key) || by_driver,
            "{key} is exposed as a limitation:\n{limitations}"
        );
    }
    // The three drivers the attributes name are stated by name.
    for driver in [
        "filter driver marker",
        "diff driver marker",
        "merge driver marker",
    ] {
        assert!(
            limitations.contains(driver),
            "{driver} is stated:\n{limitations}"
        );
    }
}

#[test]
fn a_subcommand_that_discards_the_users_work_cannot_be_run_at_all() {
    // The one place a subprocess is started refuses these, so "never clean, stash or discard
    // untracked files to start a reviewer" and "never run commit, push or destructive revert
    // merely because review was marked complete" are properties of the code rather than of the
    // call sites.
    for refused in [
        "clean",
        "stash",
        "reset",
        "restore",
        "commit",
        "push",
        "revert",
        "rebase",
        "merge",
        "cherry-pick",
        "am",
        "apply",
        "gc",
        "prune",
        "filter-branch",
        "update-ref",
        "branch",
        "rm",
        "mv",
        "add",
    ] {
        let arguments = [OsStr::new(refused)];
        let refusal =
            check_arguments(&arguments).expect_err("a subcommand outside the allowlist is refused");
        assert!(
            refusal
                .to_string()
                .contains("not a subcommand this service runs"),
            "{refused} is refused by name: {refusal}"
        );
    }
    // And no invocation carries a forced form or an override of the profile's own decisions.
    for refused in [
        "--force",
        "--force-with-lease",
        "-f",
        "-c",
        "--exec-path=/tmp",
        "--git-dir=/tmp",
        "--work-tree=/tmp",
        "--upload-pack=sh",
        "--receive-pack=sh",
        "--config-env=core.pager=X",
        "--template=/tmp/hooks",
    ] {
        let arguments = [OsStr::new("status"), OsStr::new(refused)];
        assert!(
            check_arguments(&arguments).is_err(),
            "{refused} is not an argument this service passes"
        );
    }
    // The subcommands this service does run are exactly the ones its own work needs.
    for permitted in [
        "status",
        "config",
        "rev-parse",
        "init",
        "clone",
        "worktree",
        "checkout",
        "diff",
        "symbolic-ref",
        "ls-files",
        "cat-file",
        "show-ref",
    ] {
        let arguments = [OsStr::new(permitted)];
        check_arguments(&arguments)
            .unwrap_or_else(|error| panic!("{permitted} is one this service runs: {error}"));
    }
    // An empty template is the one this host already points at, so it is allowed through.
    let arguments = [OsStr::new("clone"), OsStr::new("--template=")];
    check_arguments(&arguments).expect("an empty template names nothing");
}

#[test]
fn no_configuration_outside_the_repository_reaches_a_git_invocation() {
    // The profile sets GIT_CONFIG_NOSYSTEM and points the global and system files at a zero-byte
    // file it owns, so the only configuration an invocation sees is the repository's own. This
    // asks Git where every setting came from and checks the answer.
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "origins");
    let repository =
        OpenedRepository::open(fixture.service().profile(), fixture.environment_id(), &path)
            .expect("the repository opens");
    let arguments: [&OsStr; 4] = [
        OsStr::new("config"),
        OsStr::new("--list"),
        OsStr::new("--show-origin"),
        OsStr::new("--null"),
    ];
    let listing = fixture
        .service()
        .profile()
        .run_checked(&repository.read(&arguments))
        .expect("the configuration is listed");
    // With `--null` the records alternate: an origin, then the key and its value. So every other
    // record is an origin.
    let records: Vec<&str> = listing
        .split('\0')
        .filter(|record| !record.is_empty())
        .collect();
    let mut origins: Vec<&str> = records.iter().step_by(2).copied().collect();
    origins.sort_unstable();
    origins.dedup();
    assert!(!origins.is_empty(), "the listing named its origins");
    let top = repository.top_level().display().to_string();
    for origin in &origins {
        let acceptable = *origin == "command line:"
            // Git prints a repository-local file relative to the repository.
            || *origin == "file:.git/config"
            || *origin == "file:config.worktree"
            || origin.contains(&top)
            // The profile's own zero-byte file, named as the global or the system file.
            || origin.contains("empty-config");
        assert!(
            acceptable,
            "every setting comes from the repository, the command line or this host's own empty \
             file, and this one came from {origin}"
        );
    }
}

#[test]
fn the_audit_reads_the_repositorys_own_configuration_through_the_profile() {
    // The classifier is unit-tested against recorded listings; this proves it reads a real
    // repository's own file the same way.
    let fixture = Fixture::create();
    let planted = planted_repository(fixture.work(), "read-back", false);
    let audit = ConfigurationAudit::take(fixture.service().profile(), &planted.path)
        .expect("the configuration is read");
    assert!(
        audit
            .drivers
            .contains(&("filter".to_owned(), "marker".to_owned())),
        "the planted filter driver is found by name: {:?}",
        audit.drivers
    );
    assert!(
        audit.blanked.iter().any(|key| key == "core.fsmonitor"),
        "the planted fsmonitor is found: {:?}",
        audit.blanked
    );
    assert!(audit.refused.is_empty(), "nothing needs refusing here");
    assert_eq!(planted.escaped(), Vec::<String>::new());
}

#[test]
fn a_git_invocation_that_runs_too_long_is_stopped_and_says_so() {
    // The bound is the host's rather than the repository's, and a subprocess that outlives it is
    // ended by the handle this host holds rather than by a name or a pattern.
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "slow");
    let arguments: [&OsStr; 3] = [
        OsStr::new("config"),
        OsStr::new("--list"),
        OsStr::new("--null"),
    ];
    let request =
        GitRequest::read(&path, &arguments).with_deadline(std::time::Duration::from_nanos(1));
    let refusal = fixture
        .service()
        .profile()
        .run(&request)
        .expect_err("a deadline of a nanosecond is not met");
    assert!(
        refusal.to_string().contains("was stopped"),
        "the refusal says the invocation was stopped: {refusal}"
    );
}

#[test]
fn the_fixture_document_and_the_hosts_own_table_name_the_same_keys() {
    // The fixture is the list a person reads and the table is the list the code applies. A key in
    // one and not the other is a gap nobody would notice.
    let fixture = restricted_profile_fixture();
    for entry in fixture["neutralised"]
        .as_array()
        .expect("the fixture lists its neutralised entries")
    {
        let key = entry["key"]
            .as_str()
            .expect("each entry names its key")
            .to_ascii_lowercase();
        // A driver key is neutralised by name from the audit rather than from the table, so it is
        // the section that has to be known.
        let by_table = kr_project::git::EXECUTION_KEYS
            .iter()
            .any(|rule| rule.matches(&key));
        let by_driver = kr_project::git::DRIVER_SECTIONS
            .iter()
            .any(|(section, keys)| {
                key.starts_with(&format!("{section}."))
                    && keys
                        .iter()
                        .any(|(leaf, _)| key.ends_with(&format!(".{leaf}")))
            });
        assert!(
            by_table || by_driver,
            "{key} is in the fixture and this host has no rule for it"
        );
    }
    for entry in fixture["refused"]
        .as_array()
        .expect("the fixture lists its refused entries")
    {
        let key = entry["key"]
            .as_str()
            .expect("each entry names its key")
            .to_ascii_lowercase();
        let rule = kr_project::git::EXECUTION_KEYS
            .iter()
            .find(|rule| rule.matches(&key))
            .unwrap_or_else(|| panic!("{key} is in the fixture and this host has no rule for it"));
        assert_eq!(
            rule.disposal,
            kr_project::git::Disposal::Refuse,
            "{key} is refused rather than blanked"
        );
    }
}

#[test]
fn a_submodules_own_filter_never_runs_because_this_host_never_enters_one() {
    // A submodule's configuration lives in the parent's modules directory, which the parent's own
    // configuration listing does not read. So a driver defined there is one the audit cannot see
    // and cannot blank, and the only safe answer is never to enter the submodule. Checking a
    // submodule's dirtiness is what would enter it, so every read passes `--ignore-submodules=all`
    // and the submodules are counted from the index instead.
    let fixture = Fixture::create();
    let planted = support::planted_submodule(fixture.work(), "with-submodule");
    let repository = OpenedRepository::open(
        fixture.service().profile(),
        fixture.environment_id(),
        &planted.parent,
    )
    .expect("the parent opens");
    // The audit genuinely cannot see the submodule's driver, which is why this matters.
    assert!(
        !repository
            .audit()
            .drivers
            .iter()
            .any(|(_, name)| name == "child"),
        "the submodule's driver is invisible to the parent's audit: {:?}",
        repository.audit().drivers
    );
    let surveyed = survey(
        fixture.service().profile(),
        &repository,
        &PreviewRequest {
            project_repository_id: kr_protocol::ids::ProjectRepositoryId::new(
                kr_protocol::scalars::Uuid::from_bytes([3; 16]),
            ),
            kind: WorkspaceKind::Isolated,
            policy: include_everything(),
            base_revision: "HEAD",
            base_reference: None,
            base_change_set_id: None,
            at_ms: kr_protocol::scalars::TimestampMs::new(1),
        },
    )
    .expect("the status is read");
    assert_eq!(
        planted.escaped(),
        Vec::<String>::new(),
        "the submodule's own filter never ran"
    );
    // And the submodule is still counted and named, from the index.
    let submodules: Vec<&str> = surveyed
        .entries
        .iter()
        .filter(|entry| entry.class == kr_protocol::project::InclusionClass::Submodule)
        .map(|entry| entry.path.as_str())
        .collect();
    assert_eq!(submodules, vec![planted.submodule_path.as_str()]);
    let count = surveyed
        .preview
        .counts
        .iter()
        .find(|count| count.class == kr_protocol::project::InclusionClass::Submodule)
        .expect("the preview counts submodules");
    assert_eq!(count.total, kr_protocol::scalars::U64::new(1));
    // And the host says what it did not look at.
    assert!(
        surveyed
            .preview
            .limitations
            .iter()
            .any(|line| line.contains("does not look inside one")),
        "the limitation is stated: {:?}",
        surveyed.preview.limitations
    );
}

#[test]
fn a_driver_named_in_a_spelling_an_override_could_miss_still_never_runs() {
    // A configuration subsection is case-sensitive, and a command-line `-c` splits its argument at
    // the first equals sign. Either would let a driver survive an override that was spelled or
    // carried wrongly, so this plants both spellings in real repositories and asks for a status.
    for (name, key) in [("mixed-case", "Mixed"), ("with-equals", "with=equals")] {
        let fixture = Fixture::create();
        let path = ordinary_repository(fixture.work(), name);
        let sentinels = support::plant_named_driver(fixture.work(), &path, name, key);
        let repository =
            OpenedRepository::open(fixture.service().profile(), fixture.environment_id(), &path)
                .expect("the repository opens");
        assert!(
            repository
                .audit()
                .drivers
                .iter()
                .any(|(section, found)| section == "filter" && found == key),
            "the audit found {key} under its own spelling: {:?}",
            repository.audit().drivers
        );
        let arguments: [&OsStr; 5] = [
            OsStr::new("status"),
            OsStr::new("--porcelain=v2"),
            OsStr::new("-z"),
            OsStr::new("--untracked-files=all"),
            OsStr::new("--ignore-submodules=all"),
        ];
        fixture
            .service()
            .profile()
            .run_checked(&repository.read(&arguments))
            .expect("the status is read");
        assert!(
            !sentinels.exists(),
            "the {key} driver never ran during the status"
        );
    }
}

#[cfg(unix)]
#[test]
fn a_configuration_key_this_host_cannot_express_stops_it_reading_the_repository_at_all() {
    // A driver whose name this host cannot carry in an environment value is one whose override
    // would be for a different key. Reading the repository beside it could be reading it *through*
    // it, so nothing is read.
    use std::io::Write as _;

    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "unreadable-config");
    // Git accepts a subsection that is not valid text, and `git config` would refuse to write it,
    // so the fixture writes the configuration file itself.
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(path.join(".git/config"))
        .expect("the repository's own configuration opens");
    file.write_all(b"[filter \"bad\xffname\"]\n\tclean = /bin/echo\n")
        .expect("a subsection that is not valid text");
    drop(file);
    let refusal =
        OpenedRepository::open(fixture.service().profile(), fixture.environment_id(), &path)
            .expect_err("this host does not read a repository beside a name it cannot override");
    assert_eq!(
        refusal.code(),
        kr_protocol::error::ErrorCode::RepositoryUntrusted
    );
    assert!(
        refusal.to_string().contains("cannot express"),
        "the refusal says why: {refusal}"
    );
}

#[test]
fn a_configuration_key_that_carries_a_credential_is_not_repeated_in_a_diagnostic() {
    // A configuration key can hold a URL: `[url "https://token@host/"] insteadOf = ...` puts one
    // in the subsection, and that key travels into the limitation and the refusal.
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "credential-in-a-key");
    support::git_raw(
        &path,
        [
            "config",
            "--local",
            "--",
            "url.https://tokenuser:SECRET@example.invalid/.insteadOf",
            "kr:",
        ],
    );
    // A token in a query is as much a credential as one in user information.
    support::git_raw(
        &path,
        [
            "config",
            "--local",
            "--",
            "url.https://example.invalid/?access_token=QUERYSECRET.insteadOf",
            "kq:",
        ],
    );
    // And a driver's own name is a subsection too, so it can hold one as well.
    support::git_raw(
        &path,
        [
            "config",
            "--local",
            "--",
            "filter.https://driveruser:DRIVERSECRET@example.invalid/.clean",
            "cat",
        ],
    );
    // A quote inside a subsection is text a URL parser cannot terminate on, which is exactly why
    // a subsection is replaced rather than parsed.
    support::git_raw(
        &path,
        [
            "config",
            "--local",
            "--",
            "url.https://example.invalid/x?next=\"quoted\"&access_token=QUOTEDSECRET.insteadOf",
            "kx:",
        ],
    );
    let repository =
        OpenedRepository::open(fixture.service().profile(), fixture.environment_id(), &path)
            .expect("a read is allowed and states the limitation");
    let limitations = repository.audit().limitations().join("\n");
    assert!(
        limitations.to_ascii_lowercase().contains("insteadof"),
        "the limitation names the key: {limitations}"
    );
    // A subsection is not a URL: it is whatever the repository chose. So one that could carry a
    // credential is not parsed and not echoed, and what a person gets is the section, the leaf and
    // a fingerprint that tells two keys apart.
    assert!(
        limitations.contains("url...a-name-of") && limitations.contains("does-not-repeat"),
        "an unsafe subsection is replaced rather than parsed: {limitations}"
    );
    assert!(
        limitations.contains(".insteadof"),
        "and the leaf still says which key it was: {limitations}"
    );
    // The fingerprint is what tells two replaced names apart, so it has to be there and the two
    // url keys' replacements have to differ.
    let fingerprints: Vec<&str> = limitations
        .split("does-not-repeat-")
        .skip(1)
        .filter_map(|tail| tail.split("..").next())
        .collect();
    assert!(
        fingerprints.len() >= 3,
        "every replaced name carries one: {limitations}"
    );
    for fingerprint in &fingerprints {
        assert_eq!(fingerprint.len(), 16, "of a fixed length: {fingerprint}");
        assert!(
            fingerprint
                .chars()
                .all(|character| character.is_ascii_hexdigit()),
            "of the digest's own bytes: {fingerprint}"
        );
    }
    let mut distinct = fingerprints.clone();
    distinct.sort_unstable();
    distinct.dedup();
    assert_eq!(
        distinct.len(),
        fingerprints.len(),
        "and two different names are two different fingerprints: {fingerprints:?}"
    );
    assert!(
        limitations.contains("the filter driver ..a-name-of"),
        "a driver's own name is a subsection too: {limitations}"
    );
    for secret in [
        "SECRET",
        "QUERYSECRET",
        "DRIVERSECRET",
        "QUOTEDSECRET",
        "example.invalid",
        "tokenuser",
        "driveruser",
    ] {
        assert!(
            !limitations.contains(secret),
            "no limitation repeats what a key carried ({secret}): {limitations}"
        );
    }
    let refusal = repository
        .audit()
        .require_neutralised()
        .expect_err("taking it into the registry is refused");
    for secret in ["SECRET", "QUERYSECRET", "QUOTEDSECRET", "example.invalid"] {
        assert!(
            !refusal.to_string().contains(secret),
            "the refusal does not repeat it either ({secret}): {refusal}"
        );
    }
}

#[test]
fn the_shortest_abbreviation_of_a_forbidden_option_is_refused() {
    // Git accepts an unambiguous abbreviation of a long option, so a check that only looks at the
    // spelled-out form is a check a caller walks around. `--t` is `--template`.
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "abbreviated");
    for argument in [
        "--t=/etc",
        "--templ=/etc",
        "-qf",
        "--conf=filter.x.clean=sh",
    ] {
        let arguments = [
            std::ffi::OsStr::new("status"),
            std::ffi::OsStr::new(argument),
        ];
        let refusal = fixture
            .service()
            .profile()
            .run(&kr_project::git::GitRequest::read(&path, &arguments))
            .expect_err("an abbreviation of a forbidden option is refused");
        assert_eq!(
            refusal.code(),
            kr_protocol::error::ErrorCode::InvalidArgument,
            "{argument} is refused: {refusal}"
        );
    }
}

#[test]
fn a_credential_git_itself_prints_does_not_reach_a_caller() {
    // Git prints the configuration key and the value it objected to, so a credential can travel
    // to a caller in Git's *own* words rather than in this host's. The key here holds a URL, a
    // quote, a space and a query, which is every shape a search for a credential read wrongly.
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "git-said-it");
    let key = concat!(
        "diff.https://b.invalid/x?next=\"two words\"&access_token=GITSAIDSECRET",
        ".binary"
    );
    support::git_raw(&path, ["config", "--local", "--", key, "invalid"]);
    // Git refuses the boolean, so this is an error path rather than a successful read.
    let arguments = [
        std::ffi::OsStr::new("status"),
        std::ffi::OsStr::new("--porcelain=v2"),
    ];
    let output = fixture
        .service()
        .profile()
        .run(&kr_project::git::GitRequest::read(&path, &arguments))
        .expect("the invocation itself runs");
    assert!(
        !output.success,
        "Git refuses the value, which is the error path this test is about"
    );
    for secret in ["GITSAIDSECRET", "access_token", "two words"] {
        assert!(
            !output.stderr.contains(secret),
            "what Git said does not reach a caller with {secret} in it: {}",
            output.stderr
        );
    }
    assert!(
        output.stderr.contains("does-not-repeat"),
        "and what was taken out is named: {}",
        output.stderr
    );
    // The same through a real service call that reaches that status, whose error is what a caller
    // and the journal hold. Adoption succeeds — Git only objects to the value when it reads the
    // key for a diff — and the preview is what takes the status.
    let project = fixture
        .service()
        .project_adopt(
            &actor(),
            &ProjectAdoptParams {
                destination: destination(fixture.environment_id(), fixture.work(), "git-said-it"),
                label: "git-said-it".to_owned(),
                flow: AdoptionFlow::ExistingCheckout,
            },
            Some(&action("project.adopt", 90)),
        )
        .expect("the repository is adopted")
        .project
        .project_repository_id;
    let refusal = fixture
        .service()
        .workspace_create(
            &actor(),
            &kr_protocol::project::WorkspaceCreateParams {
                project_repository_id: project,
                label: "git-said-it".to_owned(),
                kind: WorkspaceKind::SharedExisting,
                isolation: kr_protocol::scalars::Nullable(None),
                policy: include_everything(),
                base_revision: kr_protocol::scalars::Nullable(None),
                base_change_set_id: kr_protocol::scalars::Nullable(None),
                destination: kr_protocol::scalars::Nullable(None),
                preview_only: true,
            },
            None,
        )
        .expect_err("Git refuses the value while taking the status")
        .to_string();
    for secret in ["GITSAIDSECRET", "access_token", "two words"] {
        assert!(
            !refusal.contains(secret),
            "nor through the service's own error ({secret}): {refusal}"
        );
    }
    assert!(
        refusal.contains("does-not-repeat"),
        "and that error says what it took out: {refusal}"
    );
}

#[test]
fn nothing_a_caller_or_a_repository_supplied_reaches_a_refusal() {
    // A refusal names the rule it is applying, not the text it refused. A caller can put anything
    // in a branch name, a revision or a destination, and a refusal is kept: it is answered to the
    // caller and written into the journal beside the action.
    let fixture = Fixture::create();
    let path = ordinary_repository(fixture.work(), "refusals");
    let carrying = "https://user:REFUSALSECRET@b.invalid/x";
    let mut refusals: Vec<String> = Vec::new();
    // A branch name, through `project.init`.
    refusals.push(
        fixture
            .service()
            .project_init(
                &actor(),
                &kr_protocol::project::ProjectInitParams {
                    destination: destination(fixture.environment_id(), fixture.work(), "named"),
                    label: "named".to_owned(),
                    initial_branch: kr_protocol::scalars::Nullable(Some(carrying.to_owned())),
                },
                None,
            )
            .expect_err("a branch name with a colon in it is refused")
            .to_string(),
    );
    // A revision, through a workspace creation.
    let project = fixture
        .service()
        .project_adopt(
            &actor(),
            &ProjectAdoptParams {
                destination: destination(fixture.environment_id(), fixture.work(), "refusals"),
                label: "refusals".to_owned(),
                flow: AdoptionFlow::ExistingCheckout,
            },
            Some(&action("project.adopt", 91)),
        )
        .expect("it is adopted")
        .project
        .project_repository_id;
    refusals.push(
        fixture
            .service()
            .workspace_create(
                &actor(),
                &kr_protocol::project::WorkspaceCreateParams {
                    project_repository_id: project,
                    label: "refused".to_owned(),
                    kind: WorkspaceKind::SharedExisting,
                    isolation: kr_protocol::scalars::Nullable(None),
                    policy: include_everything(),
                    base_revision: kr_protocol::scalars::Nullable(Some(carrying.to_owned())),
                    base_change_set_id: kr_protocol::scalars::Nullable(None),
                    destination: kr_protocol::scalars::Nullable(None),
                    preview_only: true,
                },
                None,
            )
            .expect_err("a revision this repository does not hold is refused")
            .to_string(),
    );
    // A destination's parent, which is not absolute.
    refusals.push(
        fixture
            .service()
            .project_init(
                &actor(),
                &kr_protocol::project::ProjectInitParams {
                    destination: kr_protocol::project::DestinationRequest {
                        environment_id: fixture.environment_id(),
                        parent_path: carrying.to_owned(),
                        name: "x".to_owned(),
                    },
                    label: "relative".to_owned(),
                    initial_branch: kr_protocol::scalars::Nullable(None),
                },
                None,
            )
            .expect_err("a parent that is not an absolute path is refused")
            .to_string(),
    );
    for refusal in &refusals {
        assert!(
            !refusal.contains("REFUSALSECRET"),
            "no refusal repeats what it refused: {refusal}"
        );
        assert!(
            refusal.contains("does-not-repeat"),
            "and each says what it took out: {refusal}"
        );
    }
    let _ = path;
}
