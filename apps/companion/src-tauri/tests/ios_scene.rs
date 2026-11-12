//! The iOS application declares one scene, and the windowing library that serves it can run it.
//!
//! An application built with the iOS 27 SDK that does not adopt UIKit's scene life cycle is ended
//! by the system at launch. The system's check reads the application's property list and nothing
//! the windowing library adds at run time, so the manifest has to be there, in the project file
//! the property list is made from and in the checked-in property list itself, and it has to name
//! the library's scene delegate. That delegate class exists only in the library's releases from
//! 0.37.0; with an older one the manifest names a class that is not there.

use std::fs;
use std::path::PathBuf;

fn read(relative: &str) -> String {
    let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), relative].iter().collect();
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{} cannot be read: {error}", path.display()))
}

/// The text with every run of white space made one space, so a rule reads the file's structure and
/// not its layout.
fn squeezed(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[test]
fn the_project_file_declares_one_scene_named_for_the_windowing_librarys_delegate() {
    let project = squeezed(&read("gen/apple/project.yml"));
    assert!(
        project.contains(
            "UIApplicationSceneManifest: UIApplicationSupportsMultipleScenes: false \
             UISceneConfigurations: UIWindowSceneSessionRoleApplication: \
             - UISceneConfigurationName: Default Configuration \
             UISceneDelegateClassName: TaoSceneDelegate"
        ),
        "project.yml does not declare one scene named TaoSceneDelegate for the application"
    );
}

#[test]
fn the_checked_in_property_list_declares_the_same_scene() {
    let plist = squeezed(&read("gen/apple/companion-tauri_iOS/Info.plist"));
    assert!(
        plist.contains(
            "<key>UIApplicationSceneManifest</key> <dict> \
             <key>UIApplicationSupportsMultipleScenes</key> <false/> \
             <key>UISceneConfigurations</key> <dict> \
             <key>UIWindowSceneSessionRoleApplication</key> <array> <dict> \
             <key>UISceneConfigurationName</key> <string>Default Configuration</string> \
             <key>UISceneDelegateClassName</key> <string>TaoSceneDelegate</string>"
        ),
        "Info.plist does not declare one scene named TaoSceneDelegate for the application"
    );
}

#[test]
fn the_locked_windowing_library_has_the_scene_delegate() {
    let lock = read("../../../Cargo.lock");
    let version = lock
        .split("[[package]]")
        .find(|package| package.trim_start().starts_with("name = \"tao\""))
        .and_then(|package| {
            package
                .lines()
                .find_map(|line| line.strip_prefix("version = \"")?.strip_suffix('"'))
        })
        .expect("Cargo.lock holds the windowing library");
    let mut parts = version
        .split('.')
        .map(|part| part.parse::<u32>().expect("a number"));
    let (major, minor) = (parts.next().unwrap(), parts.next().unwrap());
    assert!(
        (major, minor) >= (0, 37),
        "the windowing library is {version}, which has no scene delegate for the manifest to name"
    );
}
