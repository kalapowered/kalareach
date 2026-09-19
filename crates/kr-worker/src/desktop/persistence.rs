//! What a logout does to a per-user service, as a report built from the answers a host reads.
//!
//! Section 3 makes a profile's lifetime part of what the profile promises, and
//! [`LogoutPersistence`] is the vocabulary for it. Reading the two things a Linux answer turns on
//! is the platform's work: whether this host has a per-user service manager at all, and whether
//! lingering is enabled for this user. Turning those two answers into the report is not, and this
//! is where that happens.
//!
//! Keeping the two apart is what makes the answer testable. A host that reads the platform inside
//! the same function can only be tested on a host that gives the answer the test wants, which on
//! Linux means a machine with lingering enabled and a second one without it. Fed the two answers,
//! every branch is settled anywhere, including on a Mac.

use kr_protocol::desktop::LogoutPersistence;

/// What a headless worker's logout answer is made of on Linux.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinuxServices {
    /// Whether this host has a per-user service manager to ask.
    pub service_manager: bool,
    /// Whether lingering is enabled for this user, where there is a service manager to ask.
    pub lingering: bool,
}

/// The persistence, the mechanism and what a person is told, for a headless worker on Linux.
///
/// Three answers, and each says what the person can do about it.
///
/// * No per-user service manager: a worker is a detached process rather than a service, so what a
///   logout does to it is the platform's own behaviour and this host does not claim to know it.
///   That is not a choice the person could make, so it is not reported as one.
/// * Lingering enabled: the user's service manager keeps running after the logout, and a headless
///   session with it.
/// * Lingering not enabled: the manager ends with the last login session. Enabling lingering is an
///   explicit choice made outside a session, and creating a session never makes it.
#[must_use]
pub fn linux_headless(services: LinuxServices) -> (LogoutPersistence, &'static str, String) {
    if !services.service_manager {
        return (
            LogoutPersistence::NoServiceManager,
            "a detached process, reparented to the system's first process",
            "This host has no per-user service manager, so a session's worker is a detached \
             process rather than a service. What a logout does to it is the platform's own \
             behaviour and this host does not claim to know it."
                .to_owned(),
        );
    }
    let (persistence, detail) = if services.lingering {
        (
            LogoutPersistence::SurvivesLogout,
            "Lingering is enabled for this user, so the user service manager keeps running after \
             logout and a headless session with it.",
        )
    } else {
        (
            LogoutPersistence::AvailableByChoice,
            "The user service manager ends with the last login session unless lingering is \
             enabled for this user. Enabling it is an explicit choice made outside a session; \
             creating a session never enables it.",
        )
    };
    (
        persistence,
        "systemd, per-user service manager",
        detail.to_owned(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_host_with_no_service_manager_makes_no_promise_and_offers_no_choice() {
        let (persistence, mechanism, detail) = linux_headless(LinuxServices {
            service_manager: false,
            lingering: false,
        });
        assert_eq!(persistence, LogoutPersistence::NoServiceManager);
        assert!(mechanism.contains("detached process"));
        assert!(detail.contains("does not claim to know it"));
    }

    #[test]
    fn lingering_is_what_makes_a_headless_worker_outlive_the_logout() {
        let (persistence, mechanism, detail) = linux_headless(LinuxServices {
            service_manager: true,
            lingering: true,
        });
        assert_eq!(persistence, LogoutPersistence::SurvivesLogout);
        assert_eq!(mechanism, "systemd, per-user service manager");
        assert!(detail.contains("keeps running after logout"));
    }

    #[test]
    fn without_lingering_the_answer_is_a_choice_the_person_has_not_made() {
        let (persistence, mechanism, detail) = linux_headless(LinuxServices {
            service_manager: true,
            lingering: false,
        });
        assert_eq!(persistence, LogoutPersistence::AvailableByChoice);
        assert_eq!(mechanism, "systemd, per-user service manager");
        assert!(detail.contains("explicit choice"));
        assert!(
            detail.contains("creating a session never enables it"),
            "the report says what this host will not do on the person's behalf"
        );
    }

    #[test]
    fn the_lingering_answer_is_ignored_where_there_is_nothing_to_ask() {
        let (persistence, _, _) = linux_headless(LinuxServices {
            service_manager: false,
            lingering: true,
        });
        assert_eq!(
            persistence,
            LogoutPersistence::NoServiceManager,
            "a host with no service manager has no lingering setting either"
        );
    }
}
