//! Which of the scenes the system asks the application to show takes its main window.
//!
//! An application can be asked for scenes of several roles: its own, an external display's, a car's.
//! Only the application's own scene is the phone's screen.

/// The role of the application's own scene: UIKit's `UIWindowSceneSessionRoleApplication`.
const APPLICATION: &str = "UIWindowSceneSessionRoleApplication";

/// Whether a scene of this role takes the main window.
pub(crate) fn takes_the_main_window(role: &str) -> bool {
    role == APPLICATION
}

#[cfg(test)]
mod tests {
    use super::takes_the_main_window;

    #[test]
    fn the_applications_own_scene_takes_the_main_window() {
        assert!(takes_the_main_window("UIWindowSceneSessionRoleApplication"));
    }

    #[test]
    fn a_scene_of_another_role_does_not() {
        for role in [
            "UIWindowSceneSessionRoleExternalDisplayNonInteractive",
            "UIWindowSceneSessionRoleExternalDisplay",
            "CPTemplateApplicationSceneSessionRoleApplication",
            "",
        ] {
            assert!(!takes_the_main_window(role), "{role}");
        }
    }
}
