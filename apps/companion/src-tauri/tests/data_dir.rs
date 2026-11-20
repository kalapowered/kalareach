//! The companion's data folder, as the helper chooses it.

use tauri::test::{MockRuntime, mock_builder, mock_context, noop_assets};

fn app() -> tauri::App<MockRuntime> {
    mock_builder()
        .build(mock_context(noop_assets()))
        .expect("an application")
}

/// On Windows the data folder is in Local AppData, which stays on this computer, and not in
/// Roaming AppData, which a roaming profile carries to another one.
#[cfg(windows)]
#[test]
fn the_companion_data_dir_lies_under_local_app_data_and_not_roaming() {
    let app = app();
    let directory = companion_platform::companion_data_dir(&app).expect("the data folder");
    let local =
        std::path::PathBuf::from(std::env::var_os("LOCALAPPDATA").expect("LOCALAPPDATA is set"));
    let roaming = std::path::PathBuf::from(std::env::var_os("APPDATA").expect("APPDATA is set"));
    assert!(
        directory.starts_with(&local),
        "{directory:?} lies under {local:?}"
    );
    assert!(
        !directory.starts_with(&roaming),
        "{directory:?} does not lie under {roaming:?}"
    );
}

/// Where nothing roams the data folder is the one Tauri names as the application's, as it was.
#[cfg(not(windows))]
#[test]
fn the_companion_data_dir_is_the_application_data_dir_where_nothing_roams() {
    use tauri::Manager as _;

    let app = app();
    assert_eq!(
        companion_platform::companion_data_dir(&app).expect("the data folder"),
        app.path().app_data_dir().expect("the application's folder"),
    );
}
