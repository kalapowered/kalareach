//! Reading and editing this host's configuration from the command line.
//!
//! Section 23's host-and-environment group is `host.info`, `environment.list`,
//! `environment.capabilities` and `host.doctor`: four reads and no host-settings mutation. So a
//! command that changes a setting writes this user's own configuration document itself, and the
//! daemon reads the choice the next time it asks itself the question.
//!
//! Writing it here does not mean deciding here. The schema, the validation and the revision rule
//! are [`kr_protocol::hostinfo::configuration`]'s, the same ones the daemon applies, so a setting
//! written from the command line and one written by the host are the same edit.

use std::path::PathBuf;

use kr_client::shown;
use kr_client::shown::Shown;
use kr_ipc::install::{Permit, Written};
use kr_ipc::paths::EnvironmentPaths;
use kr_protocol::hostinfo::configuration::{self, Change};

use crate::error::{CliError, Result};

/// The configuration document, as a release's manifest lists it and at the version this build writes.
pub const WRITTEN: Written = Written::new("configuration", configuration::VERSION);

/// Returns where this environment's configuration document is.
#[must_use]
pub fn document_path(paths: &EnvironmentPaths) -> PathBuf {
    configuration::document_path(
        paths.state_dir(),
        paths.state_root(),
        paths.environment_id(),
    )
}

/// Reads this environment's configuration document, bounded and owner-only.
#[must_use]
pub fn load(paths: &EnvironmentPaths) -> configuration::Loaded {
    load_at(&document_path(paths))
}

/// Reads the configuration document at `path`, bounded and owner-only.
#[must_use]
pub fn load_at(path: &std::path::Path) -> configuration::Loaded {
    match configuration::read_file(
        path,
        configuration::MAX_LEN,
        kr_ipc::paths::check_configuration_file,
    ) {
        Ok(bytes) => configuration::load(bytes.as_deref()),
        Err(error) => configuration::unreadable(error),
    }
}

/// Refuses a change this environment's configuration document would refuse, with nothing written.
///
/// For a command that has something to do before the edit and must not do it for an edit that
/// will be refused. [`apply`] validates again at the moment it writes.
///
/// # Errors
///
/// Returns [`CliError::Usage`] when the edit would be refused.
pub fn validate(paths: &EnvironmentPaths, change: &Change) -> Result<()> {
    configuration::edit(&load(paths), change)
        .map(|_| ())
        .map_err(|refused| refusal(&refused))
}

/// Applies one validated change to this environment's configuration document.
///
/// Validate, then check the revision again at the last moment, then write. A document at a version
/// this build does not know, or one another writer moved while this edit was being prepared, is
/// refused with nothing written. `permit` is the release's leave to write the document at the
/// version this build writes it ([`WRITTEN`]), asked for under the writers' lock.
///
/// # Errors
///
/// Returns [`CliError::Usage`] when the edit is refused, [`CliError::Other`] when the permit is for
/// another record, and [`CliError::Ipc`] when the environment's directories cannot be made or
/// checked, or the document cannot be written.
pub fn apply(paths: &EnvironmentPaths, change: &Change, permit: &Permit<'_>) -> Result<u64> {
    apply_over(paths, change, permit, None)
}

/// [`apply`] for a change that was shown to the person against a document, and may be written only
/// over that document.
///
/// `baseline` is the document the change was prepared against and shown for. If the document on
/// disk is not that one when the writers' lock is held, nothing is written: the person confirmed a
/// change to one document, and a document that moved since is another.
///
/// # Errors
///
/// As [`apply`], and [`CliError::Usage`] when the document is not the baseline.
pub fn apply_over(
    paths: &EnvironmentPaths,
    change: &Change,
    permit: &Permit<'_>,
    baseline: Option<&configuration::Loaded>,
) -> Result<u64> {
    permit.require(&WRITTEN)?;
    // An edit is a first use of the environment as much as a daemon's start is: on a host where no
    // daemon has run yet, the state directory the lock lives in does not exist. It is made here,
    // owner-only and checked, exactly as a daemon makes it.
    paths.create()?;
    // The same lock the host takes, so a setting written here and one written by the daemon are
    // one edit at a time rather than two writers racing for the same revision.
    // The lock's own sentence names the directory it could not lock and why; this says the same
    // of the directory this command was given, without repeating a library's text.
    let held = configuration::lock(paths.state_dir()).map_err(|_| {
        CliError::Usage(shown!(
            "the configuration lock in {} is held by another writer or could not be taken",
            Shown::root(paths.state_dir())
        ))
    })?;
    let current = load(paths);
    if let Some(baseline) = baseline
        && (current.status.state != baseline.status.state
            || current.revision() != baseline.revision()
            || current.document != baseline.document)
    {
        return Err(CliError::Usage(Shown::said(
            "this host's configuration changed after it was shown for confirmation, so nothing \
             was written; run the command again",
        )));
    }
    let edited = configuration::edit(&current, change).map_err(|refused| refusal(&refused))?;
    configuration::still_current(&edited, &load(paths)).map_err(|refused| refusal(&refused))?;
    let path = document_path(paths);
    if let Some(parent) = path.parent() {
        let _ = kr_ipc::paths::create_dir_all_owner_only(parent);
    }
    kr_ipc::paths::write_owner_only_file(&path, edited.contents.as_bytes())
        .map_err(CliError::Ipc)?;
    drop(held);
    Ok(edited.revision)
}

/// The push gateways, besides the official one, that the host reports it delivers through right
/// now, from the effective configuration it answered with.
///
/// A host that does not report the setting does not know it: it would ignore the section a command
/// wrote, and go on delivering through the official gateway alone. That is said before anything is
/// written.
///
/// # Errors
///
/// Returns the refusal that says the host cannot be asked to deliver through another gateway.
pub fn push_gateways_reported(
    effective: &kr_protocol::hostinfo::EffectiveConfiguration,
) -> Result<Vec<String>> {
    let Some(row) = effective
        .values
        .iter()
        .find(|row| row.key == configuration::PUSH_GATEWAYS_KEY)
    else {
        return Err(CliError::Refused(kr_client::error::refusal(
            kr_protocol::error::ErrorCode::UnsupportedCapability,
            Shown::said(
                "this host's control daemon does not know the push gateways setting, and would \
                 ignore it: bring it to this release first",
            ),
        )));
    };
    Ok(match row.value() {
        "none" => Vec::new(),
        listed => listed.split(", ").map(str::to_owned).collect(),
    })
}

/// The push gateways the host reports it delivers through, when it says it acts on its document.
///
/// A host reports the list it holds. When it says that it cannot use the document (a host that
/// started over one closes its routes and delivers through no gateway), the list alone would
/// mislead, and that is said instead, with the host's reason.
///
/// When it says that it has not finished putting the document into force (a revocation it owes
/// could not be written down, say, or it applied the document and could not record that it had),
/// the list it reports is the one in force: the host moves the list for every document it loads,
/// whatever failed before, and ahead of the retirement of a removed gateway's credentials. What is
/// unfinished is the host's reason, and the command fails with both, because a list shown on its
/// own would suggest that the host has acted on the whole document.
///
/// # Errors
///
/// Returns why the host does not act on the document, or the refusal of
/// [`push_gateways_reported`].
pub fn push_gateways_acted_on(
    effective: &kr_protocol::hostinfo::EffectiveConfiguration,
) -> Result<Vec<String>> {
    let reported = push_gateways_reported(effective)?;
    if effective.status.state.is_a_problem() {
        return Err(CliError::Unfinished {
            code: kr_protocol::error::ErrorCode::ResourceUnavailable,
            message: shown!(
                "the host cannot use its configuration document ({}): {}",
                effective.status.state.as_str(),
                crate::shown::host_text(&effective.status.detail)
            ),
        });
    }
    if let Some(problem) = effective.not_in_force.as_ref() {
        let in_force = if reported.is_empty() {
            Shown::said("the official gateway only")
        } else {
            shown!(
                "the official gateway and {}",
                Shown::joined(reported.iter().map(|origin| Shown::address(origin)), ", ")
            )
        };
        return Err(CliError::Unfinished {
            code: kr_protocol::error::ErrorCode::ResourceUnavailable,
            message: shown!(
                "the push gateways in force are {}, and this host has not finished putting its \
                 configuration into force: {}",
                in_force,
                crate::shown::host_text(problem)
            ),
        });
    }
    Ok(reported)
}

/// What to tell a person about the routes this host sends over, when they are not the ones its
/// configuration document now selects.
///
/// A host reads the document's network, proxy and service selections once, when it starts, and
/// sends over what it read until it starts again: a document edited since, or put right after the
/// host started over one it could not use, applies at the next start. A host that started over a
/// document it could not use sends nothing to any gateway until then, though it reports the
/// document as usable once it is put right, so a list of gateways shown on its own would suggest
/// that notifications are delivered. The host says that its routes differ in the
/// `configuration-network` check of its doctor answer, a warning that also covers a selection
/// edited since the start; this says a restart is needed, and where the host says why.
///
/// A document the host cannot use now gets no note: the command says that, and a restart would
/// close the routes, not open them.
#[must_use]
pub fn routes_waiting_for_a_restart(
    result: &kr_protocol::hostinfo::HostDoctorResult,
) -> Option<Shown> {
    if result.configuration.status.state.is_a_problem() {
        return None;
    }
    result
        .checks
        .iter()
        .any(|check| {
            check.id() == NETWORK_CHECK
                && check.status == kr_protocol::hostinfo::DoctorStatus::Warning
        })
        .then(|| {
            Shown::said(
                "a restart is needed to put the routes this host's configuration document \
                 selects in force: the host sends over the routes it read when it started, and a \
                 host that started over a document it could not use sends nothing to any gateway \
                 until it restarts; the configuration-network check in kr doctor --json says \
                 which applies",
            )
        })
}

/// The identifier of the doctor check that compares the routes the host started with and the ones
/// its configuration document selects now.
const NETWORK_CHECK: &str = "configuration-network";

/// The push gateways the host delivers through after a change, when it put the change into force.
///
/// The host answers a question about its configuration only after it has put the document into
/// force, so what it reports is what it acts on. A change it could not put into force is not
/// said to have been made, and neither is one it reports differently from what was written.
///
/// # Errors
///
/// Returns why the host does not deliver through what was written.
pub fn push_gateways_in_force(
    effective: &kr_protocol::hostinfo::EffectiveConfiguration,
    written: &[String],
) -> Result<Vec<String>> {
    let reported = push_gateways_acted_on(effective)?;
    // The same gateways, whatever order the host says them in.
    let sorted = |origins: &[String]| {
        let mut origins = origins.to_vec();
        origins.sort();
        origins
    };
    if sorted(&reported) != sorted(written) {
        return Err(CliError::Unfinished {
            code: kr_protocol::error::ErrorCode::OutcomeUnknown,
            message: Shown::said(
                "the host reports other push gateways than the ones written, so the change is \
                 not in force",
            ),
        });
    }
    Ok(reported)
}

/// What a refused edit says: the configuration's own sentences, as its export rule says them.
#[must_use]
pub fn refusal(refused: &configuration::EditRefused) -> CliError {
    CliError::Usage(match refused {
        configuration::EditRefused::NotOurs(sentence) => Shown::sentence(sentence),
        configuration::EditRefused::Invalid(sentences) => {
            Shown::joined(sentences.iter().map(Shown::sentence), "; ")
        }
        configuration::EditRefused::Busy(_) => {
            Shown::said("another writer is applying an edit to this configuration")
        }
    })
}

#[cfg(test)]
mod tests {
    use kr_protocol::hostinfo::export::Sentence;

    use super::*;
    use crate::shown::marker::{MARKER, assert_unmarked, failure_renderings};

    fn reporting(
        gateways: Option<&[&str]>,
        not_in_force: Option<&'static str>,
    ) -> kr_protocol::hostinfo::EffectiveConfiguration {
        let mut effective = kr_protocol::hostinfo::EffectiveConfiguration::unread();
        if let Some(gateways) = gateways {
            effective.values = vec![configuration::push_row(
                &gateways
                    .iter()
                    .map(|&origin| origin.to_owned())
                    .collect::<Vec<_>>(),
                None,
                "/tmp/kalareach/config.json",
            )];
        }
        effective.not_in_force =
            kr_protocol::scalars::Nullable(not_in_force.map(|why| Sentence::new().stated(why)));
        effective
    }

    /// KR-REQ-16.04: the command writes a list of gateways only to a host that knows the setting,
    /// and says it made the change only when that host reports it in force.
    #[test]
    fn a_change_is_made_only_to_a_host_that_knows_the_setting_and_said_only_when_it_is_in_force() {
        const LISTED: &str = "https://push.builder.example";
        let written = vec![LISTED.to_owned()];

        // A host of an earlier release reports no such row: nothing is written for it.
        let older = reporting(None, None);
        let refused = push_gateways_reported(&older).expect_err("a host that does not know it");
        assert!(matches!(
            refused,
            CliError::Refused(ref error)
                if error.code == kr_protocol::error::ErrorCode::UnsupportedCapability
        ));

        // The control: a host that reports it, with the list in force.
        let reported = reporting(Some(&[LISTED]), None);
        assert_eq!(push_gateways_reported(&reported).expect("a row"), written);
        assert_eq!(
            push_gateways_in_force(&reported, &written).expect("in force"),
            written
        );
        assert!(
            push_gateways_reported(&reporting(Some(&[]), None))
                .expect("a row")
                .is_empty()
        );

        // A host that could not put the change into force says why, and the command does not say
        // the change was made.
        let stopped = reporting(
            Some(&[LISTED]),
            Some("a revocation could not be written down"),
        );
        assert!(matches!(
            push_gateways_in_force(&stopped, &written),
            Err(CliError::Unfinished { .. })
        ));

        // The same gateways in another order are the same list.
        let two = vec![LISTED.to_owned(), "http://127.0.0.1:8788".to_owned()];
        let reversed = reporting(Some(&["http://127.0.0.1:8788", LISTED]), None);
        assert!(push_gateways_in_force(&reversed, &two).is_ok());

        // A host that reports other gateways than the ones written has not taken the change.
        let other = reporting(Some(&["https://push.other.example"]), None);
        assert!(matches!(
            push_gateways_in_force(&other, &written),
            Err(CliError::Unfinished { .. })
        ));

        // With nothing to change, the list is shown for a document the host can use, or none, and
        // not for one it cannot use.
        for (state, shown) in [
            (configuration::DocumentState::Absent, true),
            (configuration::DocumentState::Loaded, true),
            (configuration::DocumentState::UnknownVersion, false),
            (configuration::DocumentState::Unreadable, false),
            (configuration::DocumentState::Invalid, false),
        ] {
            let mut effective = reporting(Some(&[LISTED]), None);
            effective.status.state = state;
            assert_eq!(
                push_gateways_acted_on(&effective).is_ok(),
                shown,
                "{}",
                state.as_str()
            );
        }
    }

    /// KR-REQ-16.04: a host that has not finished putting its document into force fails the
    /// command with one answer: the exit says it is unfinished, and the message says what the host
    /// delivers through and what it has not finished. A host that applied the document and could
    /// not record that it had is not said to have failed to put it into force.
    #[test]
    fn a_host_that_has_not_finished_putting_its_document_into_force_is_said_to_have_not_finished() {
        const LISTED: &str = "https://push.builder.example";
        for (list, reason) in [
            (
                &[LISTED][..],
                "this host applied the document and could not record that it had, so it will \
                 apply it again when it next starts: the registry is read-only",
            ),
            (
                &[][..],
                "the credentials of a push gateway the document does not list were not let go \
                 of, because the revocation they owe could not be written down",
            ),
        ] {
            let effective = reporting(Some(list), Some(reason));
            let Err(CliError::Unfinished { code, message }) = push_gateways_acted_on(&effective)
            else {
                panic!("a host that has not finished is not shown as done");
            };
            assert_eq!(code, kr_protocol::error::ErrorCode::ResourceUnavailable);
            let said = message.to_string();
            assert!(said.contains(reason), "the host's reason is given: {said}");
            assert_eq!(
                said.contains(LISTED),
                !list.is_empty(),
                "the list in force is named: {said}"
            );
            assert!(
                said.contains("official gateway"),
                "the official gateway is always among them: {said}"
            );
            assert!(
                !said.contains("did not put") && !said.contains("delivers"),
                "the message does not say the host failed to move a list it moved, and does not \
                 claim delivery, which a closed route would make untrue: {said}"
            );
        }
    }

    /// KR-REQ-16.04: the note that a restart is needed is given when the host's doctor answer
    /// warns that its routes differ from its document, and not otherwise: not when the check
    /// passes, not when the answer has no such check, and not for a document the host cannot use,
    /// which the command says on its own and for which a restart closes the routes.
    #[test]
    fn a_restart_is_said_to_be_needed_only_when_the_hosts_routes_differ_from_a_usable_document() {
        use kr_protocol::hostinfo::{DoctorCheck, DoctorStatus, HostDoctorResult};

        let answer = |status: Option<DoctorStatus>, state: configuration::DocumentState| {
            let checks = status
                .map(|status| {
                    DoctorCheck::new(
                        NETWORK_CHECK,
                        "This host started with the network its configuration selects",
                        status,
                        Sentence::new().stated("a check"),
                        None,
                    )
                })
                .into_iter()
                .collect();
            let mut effective = reporting(Some(&[]), None);
            effective.status.state = state;
            HostDoctorResult::new(checks, effective)
        };
        let usable = configuration::DocumentState::Loaded;

        let note = routes_waiting_for_a_restart(&answer(Some(DoctorStatus::Warning), usable))
            .expect("the routes differ from the document")
            .to_string();
        assert!(
            note.contains("restart") && note.contains("configuration-network"),
            "{note}"
        );
        assert!(routes_waiting_for_a_restart(&answer(Some(DoctorStatus::Ok), usable)).is_none());
        assert!(routes_waiting_for_a_restart(&answer(None, usable)).is_none());
        assert!(
            routes_waiting_for_a_restart(&answer(
                Some(DoctorStatus::Warning),
                configuration::DocumentState::Invalid
            ))
            .is_none()
        );
    }

    /// A refused edit says the configuration's own sentences, and a sentence that arrived from a
    /// document rather than being composed here is said by its class and length.
    #[test]
    fn a_refused_edit_does_not_repeat_a_sentence_that_arrived() {
        let arrived: Sentence =
            serde_json::from_value(serde_json::json!(MARKER)).expect("a sentence on the wire");
        for refused in [
            configuration::EditRefused::NotOurs(arrived.clone()),
            configuration::EditRefused::Invalid(vec![arrived.clone()]),
            configuration::EditRefused::Busy(MARKER.to_owned()),
        ] {
            // The negative control: the refusal's own text, which the command reported whole,
            // repeats it.
            assert!(refused.to_string().contains(MARKER), "{refused}");
            assert_unmarked("a refused edit", &failure_renderings(refusal(&refused)));
        }
        let composed = Sentence::new()
            .stated("this document is at version ")
            .number(99);
        assert_eq!(
            refusal(&configuration::EditRefused::NotOurs(composed)).to_string(),
            "this document is at version 99"
        );
    }
}
