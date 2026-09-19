//! The route to a permission the assistant cannot grant.
//!
//! Section 3 is explicit that some grants need the platform's own settings and cannot be enabled
//! programmatically. Nothing here pretends otherwise: the assistant can take somebody to the pane
//! and it cannot press the switch, and both of those are said in the interface.
//!
//! The page names a pane out of [`PANES`] and never a URL. That is the same rule the rest of this
//! boundary follows — the page supplies values, not addresses — and it is what keeps this from
//! being a general "open anything" command wearing a setup label.

use serde::Serialize;

/// One settings pane, its name for a person and the platform's own address for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Pane {
    /// The name the page asks for.
    pub id: &'static str,
    /// Where the person is going, in the platform's own words.
    pub route: &'static str,
    /// The address the platform opens that pane with.
    pub url: &'static str,
}

/// Every pane this application will open, and no others.
///
/// Each of these is a separate permission. Full Disk Access is on the list beside the others
/// rather than above them: it is a fourth grant, not a master switch, and an application holding
/// it still cannot take a screen image.
pub const PANES: &[Pane] = &[
    Pane {
        id: "accessibility",
        route: "System Settings → Privacy & Security → Accessibility",
        url: "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility",
    },
    Pane {
        id: "screen_recording",
        route: "System Settings → Privacy & Security → Screen & System Audio Recording",
        url: "x-apple.systempreferences:com.apple.preference.security?Privacy_ScreenCapture",
    },
    Pane {
        id: "full_disk_access",
        route: "System Settings → Privacy & Security → Full Disk Access",
        url: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles",
    },
    Pane {
        id: "automation",
        route: "System Settings → Privacy & Security → Automation",
        url: "x-apple.systempreferences:com.apple.preference.security?Privacy_Automation",
    },
    Pane {
        id: "microphone",
        route: "System Settings → Privacy & Security → Microphone",
        url: "x-apple.systempreferences:com.apple.preference.security?Privacy_Microphone",
    },
    Pane {
        id: "remote_desktop",
        route: "System Settings → Privacy & Security → Remote Desktop",
        url: "x-apple.systempreferences:com.apple.preference.security?Privacy_RemoteDesktop",
    },
];

/// Returns the pane with one name, where this application will open it.
#[must_use]
pub fn pane(id: &str) -> Option<&'static Pane> {
    PANES.iter().find(|pane| pane.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pane_the_application_does_not_name_is_not_opened() {
        assert!(pane("accessibility").is_some());
        assert!(pane("anything").is_none());
        assert!(
            pane("x-apple.systempreferences:com.apple.preference.security").is_none(),
            "the page names a pane, never an address"
        );
    }

    #[test]
    fn every_pane_is_a_settings_pane_and_says_where_the_person_is_going() {
        for pane in PANES {
            assert!(
                pane.url.starts_with("x-apple.systempreferences:"),
                "{} opens something that is not the platform's settings",
                pane.id
            );
            assert!(
                pane.route.contains("System Settings"),
                "{} says where the person is going",
                pane.id
            );
        }
    }

    #[test]
    fn full_disk_access_is_one_pane_among_the_others() {
        let names: Vec<&str> = PANES.iter().map(|pane| pane.id).collect();
        for separate in [
            "accessibility",
            "screen_recording",
            "full_disk_access",
            "automation",
        ] {
            assert!(names.contains(&separate), "{separate} has its own route");
        }
    }
}
