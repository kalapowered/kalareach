//! The WebView boundary, read from the files that actually configure it.
//!
//! Section 13 states the boundary as a list of rules, and each one is a fact about a file in this
//! crate: the content-security policy in `tauri.conf.json`, the capability grants in
//! `capabilities/default.json`, the command list in the crate's own source. These tests read those
//! files rather than a copy of what they should say, so a change that widens the boundary fails
//! here instead of shipping.

use std::path::{Path, PathBuf};

use companion_tauri::commands::NAMED_COMMANDS;

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(path: &Path) -> serde_json::Value {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("{} could not be read: {error}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("{} is not valid JSON: {error}", path.display()))
}

fn configuration() -> serde_json::Value {
    read(&crate_root().join("tauri.conf.json"))
}

fn capabilities() -> serde_json::Value {
    read(&crate_root().join("capabilities/default.json"))
}

/// The policy, as a map from directive to its sources.
fn policy() -> std::collections::BTreeMap<String, Vec<String>> {
    let configuration = configuration();
    let csp = configuration["app"]["security"]["csp"]
        .as_str()
        .expect("the application declares a content-security policy");
    csp.split(';')
        .filter_map(|directive| {
            let mut words = directive.split_whitespace();
            let name = words.next()?;
            Some((
                name.to_owned(),
                words.map(std::borrow::ToOwned::to_owned).collect(),
            ))
        })
        .collect()
}

/// KR-REQ-13.21: the application's interface is bundled with it, never loaded from anywhere.
#[test]
fn the_interface_is_bundled_rather_than_fetched() {
    let configuration = configuration();
    let dist = configuration["build"]["frontendDist"]
        .as_str()
        .expect("the build names where the interface comes from");
    assert!(
        !dist.starts_with("http"),
        "a built application loads its interface from the bundle, not from a service"
    );
    assert_eq!(dist, "../dist");
}

/// KR-REQ-13.21: the content-security policy allows no remote script.
#[test]
fn no_script_may_come_from_anywhere_but_the_bundle() {
    let policy = policy();
    let scripts = policy
        .get("script-src")
        .expect("the policy names where scripts may come from");
    assert_eq!(scripts, &vec!["'self'".to_owned()]);
}

/// KR-REQ-13.21: the policy permits no `unsafe-eval` and no source it does not name.
#[test]
fn the_policy_permits_no_evaluation_and_no_default_source() {
    let policy = policy();
    assert_eq!(
        policy.get("default-src"),
        Some(&vec!["'none'".to_owned()]),
        "nothing is permitted unless a directive names it"
    );
    for (directive, sources) in &policy {
        assert!(
            !sources.iter().any(|source| source == "'unsafe-eval'"),
            "{directive} permits evaluation"
        );
        assert!(
            !sources.iter().any(|source| source == "*"),
            "{directive} permits anything"
        );
    }
}

#[test]
fn nothing_may_be_embedded_framed_or_navigated_away() {
    let policy = policy();
    for directive in ["object-src", "frame-src", "child-src", "form-action"] {
        assert_eq!(
            policy.get(directive),
            Some(&vec!["'none'".to_owned()]),
            "{directive} should permit nothing"
        );
    }
    assert_eq!(policy.get("base-uri"), Some(&vec!["'none'".to_owned()]));
    assert_eq!(
        policy.get("frame-ancestors"),
        Some(&vec!["'none'".to_owned()])
    );
}

#[test]
fn an_image_may_come_only_from_the_bundle_or_from_bytes_the_application_produced() {
    let policy = policy();
    let images = policy
        .get("img-src")
        .expect("the policy names where images may come from");
    for source in images {
        assert!(
            matches!(source.as_str(), "'self'" | "data:" | "blob:"),
            "img-src permits {source}, which is not the bundle or this application's own bytes"
        );
    }
    assert!(
        !images.iter().any(|source| source.starts_with("http")),
        "an image is never fetched from a remote origin by the page"
    );
}

/// KR-REQ-10.01: the WebView connects to nothing but the application's own IPC channel.
#[test]
fn nothing_connects_anywhere_but_the_applications_own_channel() {
    let policy = policy();
    let connect = policy
        .get("connect-src")
        .expect("the policy names what the page may connect to");
    for source in connect {
        assert!(
            matches!(source.as_str(), "'self'" | "ipc:" | "http://ipc.localhost"),
            "connect-src permits {source}, which is not this application's own channel"
        );
    }
}

/// KR-REQ-10.01: the WebView holds no shell, filesystem or general network capability.
/// KR-REQ-13.21: the web view is granted no shell execution, no filesystem paths and no general
/// network access.
#[test]
fn the_capabilities_grant_no_shell_no_filesystem_and_no_general_http() {
    let capabilities = capabilities();
    let granted: Vec<String> = capabilities["permissions"]
        .as_array()
        .expect("the capability file lists its permissions")
        .iter()
        .map(|permission| match permission {
            serde_json::Value::String(name) => name.clone(),
            other => other["identifier"]
                .as_str()
                .expect("a permission names itself")
                .to_owned(),
        })
        .collect();

    // The pasteboard is read in native code, where an invitation's text stays, so the page is
    // granted no clipboard permission at all.
    for forbidden in [
        "shell:",
        "fs:",
        "http:",
        "process:",
        "os:",
        "clipboard-manager:",
    ] {
        assert!(
            !granted.iter().any(|name| name.starts_with(forbidden)),
            "the interface is granted {forbidden}, which the boundary does not permit"
        );
    }
    assert!(
        !granted.iter().any(|name| name == "core:default"),
        "the core default set includes emitting events, which is more than the interface needs"
    );
    assert!(
        !granted
            .iter()
            .any(|name| name.starts_with("core:event:allow-emit")),
        "an event the page can emit is an event it can use to tell the backend something happened"
    );
    assert!(
        granted.iter().any(|name| name == "core:event:allow-listen"),
        "the interface listens for the host's events"
    );
    assert!(
        granted.iter().any(|name| name == "dialog:allow-save"),
        "an export needs the platform's own save dialog"
    );
}

/// Section 13: external links require a user action and approved schemes. The page opens nothing
/// itself: no opener command is granted to it, on any platform, so a script in the page cannot
/// hand the system browser an address. A link opens through `open_external`, which applies the
/// application's own scheme list, and the sign-in opens the browser from the backend alone.
#[test]
fn the_page_opens_nothing_itself_and_a_link_goes_through_the_scheme_policy() {
    for (file, capabilities) in [
        ("default.json", capabilities()),
        ("mobile.json", mobile_capabilities()),
    ] {
        let granted = granted(&capabilities);
        assert!(
            !granted.iter().any(|name| name.starts_with("opener:")),
            "{file} lets the page open an address itself: {granted:?}"
        );
        assert!(
            !granted
                .iter()
                .any(|name| name.starts_with("companion-platform:")),
            "{file} lets the page reach the platform plugin's native methods: {granted:?}"
        );
    }
    assert_eq!(
        companion_tauri::links::APPROVED_SCHEMES,
        ["https", "mailto"]
    );
    assert!(
        NAMED_COMMANDS
            .iter()
            .any(|(command, method)| *command == "open_external" && method.is_none()),
        "a link the person follows still opens, through the scheme policy"
    );
}

/// KR-REQ-17.19: the account's commands are the application's own, and none of them is a host
/// method or takes an address from the page.
#[test]
fn the_account_is_reached_through_five_named_commands() {
    let account: Vec<&str> = NAMED_COMMANDS
        .iter()
        .filter(|(command, _)| command.starts_with("account_"))
        .map(|(command, method)| {
            assert!(method.is_none(), "{command} is not a host method");
            *command
        })
        .collect();
    assert_eq!(
        account,
        [
            "account_status",
            "account_sign_in",
            "account_sign_in_cancel",
            "account_sign_out",
            "account_usage"
        ]
    );
}

#[test]
fn the_asset_protocol_is_off_and_the_bridge_is_not_a_global() {
    let configuration = configuration();
    assert_eq!(
        configuration["app"]["security"]["assetProtocol"]["enable"],
        serde_json::Value::Bool(false),
        "there is no protocol that turns a path into a readable URL"
    );
    // Freezing `Object.prototype` is stated, and stated false. The terminal library writes
    // `toString` onto one of its own namespace objects while it is being evaluated, and an
    // inherited property that has been frozen makes that assignment throw, which leaves the
    // window empty. The page loads no script it did not ship, so the setting is named here rather
    // than left to a default that a later version could flip.
    assert_eq!(
        configuration["app"]["security"]["freezePrototype"],
        serde_json::Value::Bool(false),
        "the setting is stated, because the terminal library cannot run under a frozen prototype"
    );
    assert_eq!(
        configuration["app"]["withGlobalTauri"],
        serde_json::Value::Bool(false),
        "the command bridge is not a global the page can reach without importing it"
    );
}

/// KR-REQ-13.21: the page can call only the commands this crate names.
#[test]
fn every_command_the_page_can_call_is_one_this_crate_names() {
    // The handler list is generated from the same names, so this is the list as data: a command
    // that exists without an entry here, or an entry without a command, is a boundary that two
    // files disagree about.
    let named: Vec<&str> = NAMED_COMMANDS.iter().map(|(command, _)| *command).collect();
    let source = std::fs::read_to_string(crate_root().join("src/commands.rs"))
        .expect("the command module is readable");
    let handlers = source
        .split("tauri::generate_handler![")
        .nth(1)
        .and_then(|rest| rest.split(']').next())
        .expect("the handler list is generated in this module");
    let registered: Vec<String> = handlers
        .split(',')
        .map(|name| name.trim().to_owned())
        .filter(|name| !name.is_empty())
        .collect();

    for command in &named {
        assert!(
            registered.iter().any(|name| name == command),
            "{command} is named but not registered"
        );
    }
    for command in &registered {
        assert!(
            named.iter().any(|name| name == command),
            "{command} is registered but not named"
        );
    }
}

#[test]
fn no_command_is_a_shell_a_path_or_a_method_the_page_chooses() {
    for (command, _) in NAMED_COMMANDS {
        let lowered = command.to_ascii_lowercase();
        // `shell_launch` is the specification's own name for installing a command at a verified
        // empty prompt, and it is a protocol method with its own preconditions rather than a
        // general shell. Every other shape of general execution is what this refuses.
        if *command == "shell_launch" {
            continue;
        }
        for forbidden in [
            "exec",
            "shell",
            "spawn",
            "eval",
            "read_file",
            "write_file",
            "invoke",
        ] {
            assert!(
                !lowered.contains(forbidden),
                "{command} reads as a general {forbidden}"
            );
        }
    }
}

/* ---- The mobile targets ---------------------------------------------------------------------
 *
 * A phone is the same boundary as a desktop window with one addition: the file picker, which is
 * how a WebView reaches the camera, the photo library and the file browser on both platforms. The
 * tests below hold the mobile capability to that addition and nothing else, and hold the mobile
 * bundle blocks to naming a platform floor without inventing an identity only a release can have.
 */

fn mobile_capabilities() -> serde_json::Value {
    read(&crate_root().join("capabilities/mobile.json"))
}

/// The permissions a capability file grants, whether each is named plainly or with a scope.
fn granted(capabilities: &serde_json::Value) -> Vec<String> {
    capabilities["permissions"]
        .as_array()
        .expect("the capability file lists its permissions")
        .iter()
        .map(|permission| match permission {
            serde_json::Value::String(name) => name.clone(),
            other => other["identifier"]
                .as_str()
                .expect("a permission names itself")
                .to_owned(),
        })
        .collect()
}

#[test]
fn the_mobile_capability_applies_only_to_the_two_mobile_platforms() {
    let capabilities = mobile_capabilities();
    let platforms: Vec<String> = capabilities["platforms"]
        .as_array()
        .expect("a capability that is not for every platform names the ones it is for")
        .iter()
        .map(|platform| platform.as_str().expect("a platform name").to_owned())
        .collect();
    assert_eq!(platforms, vec!["iOS".to_owned(), "android".to_owned()]);
    assert_eq!(
        capabilities["windows"],
        serde_json::json!(["main"]),
        "the grant is to the application's own window and to no other"
    );
    assert_eq!(
        capabilities["local"],
        serde_json::Value::Bool(true),
        "the grant is to the bundled interface, never to remote content"
    );
}

/// KR-REQ-13.08: a phone is granted what every platform is granted, from a capability that names no
/// platform, and one addition of its own: the platform's file picker. The addition reaches no
/// shell, filesystem, network, process or event emission.
#[test]
fn the_mobile_capability_is_no_wider_than_the_desktop_one() {
    let common = capabilities();
    assert!(
        common["platforms"].is_null(),
        "the common grant is every platform's, the phones' included"
    );
    let mobile = granted(&mobile_capabilities());
    assert!(
        mobile.iter().all(|name| !granted(&common).contains(name)),
        "the mobile capability holds only what the common grant does not"
    );

    for forbidden in ["shell:", "fs:", "http:", "process:", "os:"] {
        assert!(
            !mobile.iter().any(|name| name.starts_with(forbidden)),
            "the mobile interface is granted {forbidden}, which the boundary does not permit"
        );
    }
    assert!(
        !mobile.iter().any(|name| name == "core:default"),
        "the core default set includes emitting events, which is more than a phone needs either"
    );
    assert!(
        !mobile
            .iter()
            .any(|name| name.starts_with("core:event:allow-emit")),
        "a page that can emit an event can tell the backend something happened that did not"
    );
    // The one addition, and the reason for the file: a picker is the platform's own camera, photo
    // library and file browser, and it hands the page what the person chose rather than a path.
    assert_eq!(
        mobile,
        vec!["dialog:allow-open".to_owned()],
        "the mobile grant is the file picker and nothing else"
    );
}

/// KR-REQ-13.08: every platform's build carries the one bundled interface; no platform points it
/// somewhere else.
#[test]
fn the_mobile_builds_carry_the_interface_in_the_bundle() {
    let configuration = configuration();
    // The same fact the desktop build states, restated for the phones: section 13 forbids a
    // production application loading its own code from the managed service, and the one place
    // that could happen is the configuration that says where the interface comes from.
    let dist = configuration["build"]["frontendDist"]
        .as_str()
        .expect("the build names where the interface comes from");
    assert!(!dist.starts_with("http"));
    for platform in ["iOS", "android"] {
        let block = &configuration["bundle"][platform];
        assert!(
            block.is_object(),
            "the {platform} bundle block states this build's platform floor"
        );
        assert!(
            block["frontendDist"].is_null(),
            "no platform may point the interface somewhere else"
        );
    }
}

#[test]
fn the_mobile_bundle_names_a_platform_floor_and_no_release_identity() {
    let configuration = configuration();
    assert_eq!(
        configuration["bundle"]["iOS"]["minimumSystemVersion"],
        serde_json::json!("17.0")
    );
    assert_eq!(
        configuration["bundle"]["android"]["minSdkVersion"],
        serde_json::json!(29)
    );
    // A signing identity, a development team and a provisioning profile are not stated in the
    // Tauri configuration: inventing one here would produce a build that looks signed and is not.
    // The one thing the repository does name is the Apple team, once, in the iOS project, which the
    // identifier test below holds; the certificate and the profile belong to whoever signs.
    for invented in [
        "developmentTeam",
        "provisioningProfile",
        "signingIdentity",
        "certificate",
    ] {
        assert!(
            configuration["bundle"]["iOS"][invented].is_null(),
            "the iOS bundle block states {invented}, which is a release decision"
        );
        assert!(
            configuration["bundle"]["android"][invented].is_null(),
            "the Android bundle block states {invented}, which is a release decision"
        );
    }
}

#[test]
fn first_start_setup_reaches_three_named_commands_and_no_more() {
    // Setup reads what may be done on this desktop, reads the identity a grant would be filed
    // under, and opens a settings pane by name. That is the whole of its surface: there is no
    // command here that grants a permission, writes a setting or opens an address the page chose.
    let named: Vec<&str> = NAMED_COMMANDS.iter().map(|(command, _)| *command).collect();
    let setup: Vec<&&str> = named
        .iter()
        .filter(|command| command.starts_with("setup_"))
        .collect();
    assert_eq!(
        setup,
        vec![&"setup_identity", &"setup_open_settings"],
        "setup's own commands are exactly these two"
    );
    assert!(
        named.contains(&"environment_capabilities"),
        "the assistant reads the capability records through a named command"
    );
    for (command, method) in NAMED_COMMANDS {
        if *command == "environment_capabilities" {
            assert_eq!(
                *method,
                Some(kr_protocol::method::Method::EnvironmentCapabilities),
                "the capabilities command performs one operation and names it"
            );
        }
        if command.starts_with("setup_") {
            assert_eq!(
                *method, None,
                "{command} is this application's own, not a protocol operation"
            );
        }
    }
}

#[test]
fn a_settings_pane_is_opened_by_name_and_never_by_an_address_the_page_supplies() {
    for pane in companion_tauri::setup::settings::PANES {
        assert!(
            !pane.id.contains(':') && !pane.id.contains('/'),
            "{} reads as an address rather than a name",
            pane.id
        );
    }
    assert!(
        companion_tauri::setup::settings::pane(
            "x-apple.systempreferences:com.apple.preference.security"
        )
        .is_none(),
        "an address is not a pane name"
    );
    assert!(
        companion_tauri::setup::settings::pane("https://example.org").is_none(),
        "the setup route does not open a web address"
    );
}

/// KR-REQ-13.08: the desktop and mobile applications build on the one native client library.
/// `kr-client` is a dependency of this crate for every platform, and the desktop platforms add a
/// feature to that same library rather than naming a client of their own.
#[test]
fn every_platform_builds_on_the_one_native_client_library() {
    let manifest = std::fs::read_to_string(crate_root().join("Cargo.toml"))
        .expect("the crate's manifest can be read");
    let mut section = String::new();
    let mut everywhere = false;
    let mut per_platform = Vec::new();
    for line in manifest.lines() {
        let line = line.trim_end();
        if let Some(name) = line
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
        {
            section = name.to_owned();
            continue;
        }
        if !line.starts_with("kr-client") {
            continue;
        }
        if section == "dependencies" {
            everywhere = true;
        } else if section.ends_with(".dependencies") && section.starts_with("target.") {
            per_platform.push((section.clone(), line.to_owned()));
        }
    }
    assert!(
        everywhere,
        "kr-client is a dependency of every platform's build"
    );
    for (section, line) in &per_platform {
        assert!(
            line.starts_with("kr-client = { workspace = true, features"),
            "{section} adds features to the same library rather than another client: {line}"
        );
    }
    assert!(
        !manifest.contains("kr-client-mobile") && !manifest.contains("kr-client-desktop"),
        "no platform has a client of its own"
    );
}

/// The application identifier on every platform is the one the website's association documents
/// and the push service's registered apps name, so the phone's sign-in can come back to it.
///
/// Apple honours an HTTPS callback only for the bundle the domain's association names, and Android
/// hands a verified link only to the package the domain's asset links name; both name
/// `to.kala.reach`. The keychain groups and the extension's identifier follow from it.
#[test]
fn the_application_identifier_is_the_one_the_website_associates_on_every_platform() {
    const IDENTIFIER: &str = "to.kala.reach";
    let root = crate_root();
    let text = |relative: &str| {
        std::fs::read_to_string(root.join(relative))
            .unwrap_or_else(|error| panic!("{relative} could not be read: {error}"))
    };
    assert_eq!(configuration()["identifier"], serde_json::json!(IDENTIFIER));

    let project = text("gen/apple/project.yml");
    for expected in [
        "  bundleIdPrefix: to.kala.reach\n",
        "      PRODUCT_BUNDLE_IDENTIFIER: to.kala.reach\n",
        "        PRODUCT_BUNDLE_IDENTIFIER: to.kala.reach.notifications\n",
        "        PRODUCT_BUNDLE_IDENTIFIER: to.kala.reach.native-tests\n",
        "        KRPrivateKeychainGroup: $(AppIdentifierPrefix)to.kala.reach\n",
        "        KRSharedKeychainGroup: $(AppIdentifierPrefix)to.kala.reach.shared\n",
    ] {
        assert!(project.contains(expected), "project.yml lacks {expected:?}");
    }
    // One Apple team for every target: the prefix of each keychain group and of the application
    // identifier the website's association names. The project chooses no certificate and no
    // provisioning profile; whoever signs does.
    assert_eq!(
        project.matches("DEVELOPMENT_TEAM:").count(),
        1,
        "project.yml names the team once, for every target"
    );
    assert!(
        project.contains("\nsettings:\n  base:\n    DEVELOPMENT_TEAM: L775WGST9V\n"),
        "the project names the organisation's Apple team"
    );
    for chosen_by_the_signer in [
        "CODE_SIGN_IDENTITY",
        "PROVISIONING_PROFILE",
        "CODE_SIGN_STYLE",
    ] {
        assert!(
            !project.contains(chosen_by_the_signer),
            "project.yml names {chosen_by_the_signer}, which belongs to whoever signs"
        );
    }
    // The application's own group first: the platform files an item written without a group
    // under the first one, and the extension may read the shared one.
    let application = project
        .split("  companion-tauri_iOS:\n")
        .nth(1)
        .expect("project.yml describes the application target");
    let groups = application
        .split("keychain-access-groups:\n")
        .nth(1)
        .expect("the application declares its keychain groups");
    let listed: Vec<&str> = groups.lines().take(2).map(str::trim).collect();
    assert_eq!(
        listed,
        [
            "- $(AppIdentifierPrefix)to.kala.reach",
            "- $(AppIdentifierPrefix)to.kala.reach.shared"
        ]
    );

    // The sign-in's HTTPS callback and the credentials association belong to this application
    // alone: the extension needs neither, and the website's association names the application.
    let entitlements = text("gen/apple/companion-tauri_iOS/companion-tauri_iOS.entitlements");
    for domain in ["applinks:reach.kala.to", "webcredentials:reach.kala.to"] {
        assert!(
            project.contains(&format!("          - {domain}\n")),
            "project.yml lacks the associated domain {domain}"
        );
        assert!(
            entitlements.contains(&format!("<string>{domain}</string>")),
            "the application's entitlements lack the associated domain {domain}"
        );
    }
    assert!(
        !text("gen/apple/KalaReachNotificationService/KalaReachNotificationService.entitlements")
            .contains("associated-domains"),
        "the extension declares no associated domain"
    );

    // What the project generator wrote from it agrees.
    let pbxproj = text("gen/apple/companion-tauri.xcodeproj/project.pbxproj");
    let identifiers: Vec<String> = pbxproj
        .lines()
        .filter_map(|line| line.trim().strip_prefix("PRODUCT_BUNDLE_IDENTIFIER = "))
        .map(|value| value.trim_end_matches(';').trim_matches('"').to_owned())
        .collect();
    assert_eq!(identifiers.len(), 6, "{identifiers:?}");
    for identifier in &identifiers {
        assert!(
            [
                "to.kala.reach",
                "to.kala.reach.notifications",
                "to.kala.reach.native-tests"
            ]
            .contains(&identifier.as_str()),
            "the generated project names {identifier}"
        );
    }
    // The team reaches the project Xcode reads: every value in it is the one team, and none is
    // narrowed to a single SDK, which would leave a build for another SDK under a different team.
    assert!(
        !pbxproj.contains("DEVELOPMENT_TEAM["),
        "the generated project narrows its team to one SDK"
    );
    let teams: Vec<&str> = pbxproj
        .lines()
        .filter_map(|line| line.trim().strip_prefix("DEVELOPMENT_TEAM = "))
        .collect();
    assert!(!teams.is_empty(), "the generated project names no team");
    for team in teams {
        assert_eq!(
            team, "L775WGST9V;",
            "the generated project names another team"
        );
    }
    for generated in [
        "gen/apple/companion-tauri_iOS/Info.plist",
        "gen/apple/companion-tauri_iOS/companion-tauri_iOS.entitlements",
        "gen/apple/KalaReachNotificationService/Info.plist",
        "gen/apple/KalaReachNotificationService/KalaReachNotificationService.entitlements",
    ] {
        let content = text(generated);
        assert!(
            content.contains("$(AppIdentifierPrefix)to.kala.reach.shared</string>"),
            "{generated} names the shared group"
        );
        assert!(
            !content.contains("to.kala.reach.companion"),
            "{generated} still names the old identifier"
        );
    }

    let gradle = text("gen/android/app/build.gradle.kts");
    assert!(gradle.contains("    namespace = \"to.kala.reach\"\n"));
    assert!(gradle.contains("        applicationId = \"to.kala.reach\"\n"));
    // The activity sits in the package the generated activity classes and the native entry
    // points are derived into, which is the identifier itself.
    assert!(
        text("gen/android/app/src/main/java/to/kala/reach/MainActivity.kt")
            .starts_with("package to.kala.reach\n")
    );
    assert!(
        !root
            .join("gen/android/app/src/main/java/to/kala/reach/companion/MainActivity.kt")
            .exists()
    );
}

/// Push on iOS is wired the way the project's owner decided, and a build that cannot reach Firebase
/// still launches.
///
/// Firebase's own hook into the application delegate is off, because the delegate belongs to the
/// windowing library and the hook would wrap methods of it that have nothing to do with push;
/// registration tokens are not made until the person agrees to notifications; only the messaging
/// library is linked, so no analytics installation is written; the library is pinned by revision,
/// and the application's deployment target is the one the library and the bundle configuration
/// name. The configuration file is the build owner's, never the repository's.
#[test]
fn push_on_ios_is_wired_without_borrowing_the_delegate_or_the_account_configuration() {
    let root = crate_root();
    let text = |relative: &str| {
        std::fs::read_to_string(root.join(relative))
            .unwrap_or_else(|error| panic!("{relative} could not be read: {error}"))
    };
    let project = text("gen/apple/project.yml");
    for expected in [
        "        FirebaseAppDelegateProxyEnabled: false\n",
        "        FirebaseMessagingAutoInitEnabled: false\n",
        "      - package: Firebase\n        product: FirebaseMessaging\n",
        "    iOS: 17.0\n",
    ] {
        assert!(project.contains(expected), "project.yml lacks {expected:?}");
    }
    assert!(
        !project.contains("FirebaseAnalytics") && !project.contains("product: FirebaseCore"),
        "only the messaging library is linked"
    );
    let revision = project
        .split("  Firebase:\n")
        .nth(1)
        .and_then(|section| {
            section
                .lines()
                .find_map(|line| line.trim().strip_prefix("revision: "))
        })
        .expect("the Firebase package is pinned by revision");
    assert!(
        revision.len() == 40 && revision.chars().all(|each| each.is_ascii_hexdigit()),
        "the Firebase revision is a full commit: {revision}"
    );
    assert_eq!(
        configuration()["bundle"]["iOS"]["minimumSystemVersion"],
        serde_json::json!("17.0"),
        "the bundle and the project agree on the deployment target"
    );

    // The launch code is the application's alone: the native tests build the decisions without the
    // Firebase library and without a launch.
    let target = |name: &str| {
        let after = project
            .split(&format!("  {name}:\n"))
            .nth(1)
            .unwrap_or_else(|| panic!("project.yml describes {name}"));
        // The target ends at the next line indented by exactly one level.
        let mut block = String::new();
        for line in after.lines() {
            let one_level = line.starts_with("  ") && !line.starts_with("   ");
            if one_level && !line.trim().is_empty() && !line.trim_start().starts_with('#') {
                break;
            }
            block.push_str(line);
            block.push('\n');
        }
        block
    };
    assert!(
        project.contains("native/ios/KalaReachApp"),
        "the application compiles the launch code"
    );
    for other in ["KalaReachNativeTests", "KalaReachNotificationService"] {
        assert!(
            !target(other).contains("KalaReachApp"),
            "{other} must not compile the application's launch code"
        );
    }

    // The configuration is the account's, so the repository holds none and ignores the local file
    // that names where it is.
    let ignored = text("gen/apple/.gitignore");
    assert!(
        ignored.lines().any(|line| line == "Local.xcconfig"),
        "the machine-local build settings are ignored"
    );
    let tracked = String::from_utf8(
        std::process::Command::new("git")
            .args(["ls-files", "--", "."])
            .current_dir(&root)
            .output()
            .expect("git runs")
            .stdout,
    )
    .expect("git lists paths as text");
    assert!(
        !tracked
            .lines()
            .any(|line| line.ends_with("GoogleService-Info.plist")
                || line.ends_with("Local.xcconfig")),
        "the repository holds an account's Firebase configuration or a machine's settings"
    );
}

/// Every file of the application that the repository holds, as a path relative to it.
///
/// What a build leaves beside them (generated projects, caches, symbolic links to libraries) is
/// not what ships, and reading it would make this test depend on what happened to be built here. A
/// file that is new and not yet staged is listed as well, so a local run reads what a commit will.
fn repository_files(application: &Path) -> Vec<String> {
    let listed = std::process::Command::new("git")
        .args([
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ])
        .current_dir(application)
        .output()
        .expect("git can list the application's files");
    assert!(
        listed.status.success(),
        "git could not list the application's files: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let mut names: Vec<String> = listed
        .stdout
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
        .map(|name| String::from_utf8(name.to_vec()).expect("a file has a UTF-8 name"))
        .collect();
    names.sort();
    names.dedup();
    names
}

/// The dotted name a line holds at `at`, up to the first character a name cannot hold.
fn dotted_name_at(line: &str, at: usize) -> &str {
    let rest = &line[at..];
    let end = rest
        .find(|character: char| !(character.is_alphanumeric() || "_.$".contains(character)))
        .unwrap_or(rest.len());
    &rest[..end]
}

/// Whether a dotted name under the namespace is a class: package names in lower case, if any, and
/// then a class name that starts with a capital and has a lower-case letter in it, which is what
/// tells `PreviewWorker` from a constant such as `START`. With `or_package`, a trailing dot makes
/// it the prefix of a package. `to.kala.reach.companion.fileprovider` and
/// `to.kala.reach.companion.permission.READ` are names a build would file state under, not classes.
fn names_a_class(name: &str, namespace: &str, or_package: bool) -> bool {
    let Some(rest) = name
        .strip_prefix(namespace)
        .and_then(|rest| rest.strip_prefix('.'))
    else {
        return false;
    };
    let mut segments: Vec<&str> = rest.split('.').collect();
    let last = segments.pop().unwrap_or("");
    let package = |segment: &str| segment.chars().next().is_some_and(char::is_lowercase);
    let class =
        last.chars().next().is_some_and(char::is_uppercase) && last.chars().any(char::is_lowercase);
    segments.iter().all(|segment| package(segment))
        && (class || (or_package && last.is_empty() && !segments.is_empty()))
}

const KEPT_NAMESPACE: &str = "to.kala.reach.companion";
const MANIFEST: &str = "src-tauri/gen/android/app/src/main/AndroidManifest.xml";
/// The packaging check's scripts, which name the classes the packaged application must carry.
const NAMES_CLASSES: [&str; 2] = [
    "scripts/android-classes.mjs",
    "scripts/android-classes-selftest.mjs",
];

/// Whether a line of `file` may hold the Kotlin and Java namespace the application keeps: where it
/// names a package or a class, which is a `package` or `import` line, the manifest's component
/// classes, and the class and package names the packaging check lists. A name under the namespace
/// anywhere else, a notification channel or an authority or a permission or a store, is a name that
/// should have followed the application identifier.
fn may_hold_the_namespace(file: &str, line: &str) -> bool {
    let trimmed = line.trim_start();
    if trimmed.starts_with(&format!("package {KEPT_NAMESPACE}"))
        || trimmed.starts_with(&format!("import {KEPT_NAMESPACE}"))
    {
        return true;
    }
    line.match_indices(KEPT_NAMESPACE).all(|(at, _)| {
        let name = dotted_name_at(line, at);
        if file == MANIFEST {
            // A component's name, on a line that holds nothing else.
            let alone = trimmed
                .strip_prefix("android:name=\"")
                .and_then(|rest| rest.strip_suffix('"'));
            alone == Some(name) && names_a_class(name, KEPT_NAMESPACE, false)
        } else {
            NAMES_CLASSES.contains(&file) && names_a_class(name, KEPT_NAMESPACE, true)
        }
    })
}

#[test]
fn the_namespace_is_held_only_where_it_names_a_class_or_a_package() {
    let component =
        "            android:name=\"to.kala.reach.companion.push.KalaReachMessagingService\"";
    assert!(may_hold_the_namespace(MANIFEST, component));
    assert!(may_hold_the_namespace(
        MANIFEST,
        "            android:name=\"to.kala.reach.companion.Bridge\""
    ));
    // A permission, an authority, a store and a channel are filed under the identifier.
    for refused in [
        "android:name=\"to.kala.reach.companion.permission.READ\"",
        "android:authorities=\"to.kala.reach.companion.push.Share\"",
        "android:authorities=\"to.kala.reach.companion.fileprovider\"",
        "<meta-data android:value=\"to.kala.reach.companion.push.Alerts\" />",
        "android:name=\"to.kala.reach.companion.voice.START\"",
        "android:name=\"to.kala.reach.companion.Bridge\" android:authorities=\"to.kala.reach.companion.push.Share\"",
    ] {
        assert!(!may_hold_the_namespace(MANIFEST, refused), "{refused}");
    }
    let script = "  'to.kala.reach.companion.push.PreviewWorker'";
    assert!(may_hold_the_namespace(
        "scripts/android-classes.mjs",
        script
    ));
    assert!(may_hold_the_namespace(
        "scripts/android-classes.mjs",
        "const HAND_WRITTEN = ['to.kala.reach.companion.push.', 'to.kala.reach.companion.mobile.']"
    ));
    assert!(!may_hold_the_namespace(
        "scripts/android-classes.mjs",
        "'to.kala.reach.companion.push'"
    ));
    // Anywhere else only a package or an import line holds it.
    assert!(!may_hold_the_namespace(
        "native/x/Alerts.kt",
        "const val X = \"to.kala.reach.companion.push\""
    ));
    assert!(may_hold_the_namespace(
        "native/x/Alerts.kt",
        "import to.kala.reach.companion.mobile.Sealer"
    ));
    assert!(!names_a_class(
        "to.kala.reach.companion",
        KEPT_NAMESPACE,
        true
    ));
    assert!(names_a_class(
        "to.kala.reach.companion.push.",
        KEPT_NAMESPACE,
        true
    ));
    assert!(!names_a_class(
        "to.kala.reach.companion.push.",
        KEPT_NAMESPACE,
        false
    ));
}

/// The names an earlier identifier and an earlier Apple team gave the application are gone.
///
/// The Kotlin and Java package `to.kala.reach.companion` stays, and `may_hold_the_namespace` says
/// where it may appear.
#[test]
fn no_file_names_an_identifier_or_a_team_the_application_no_longer_has() {
    // These name the retired spellings in order to refuse them.
    const REFUSES_THEM: [&str; 3] = [
        "src-tauri/tests/boundary.rs",
        "scripts/identifiers.mjs",
        "scripts/identifiers-selftest.mjs",
    ];
    let application = crate_root()
        .parent()
        .expect("the crate sits inside the application's directory")
        .to_owned();
    let files = repository_files(&application);
    assert!(
        files.len() > 100,
        "the application's files were listed: {}",
        files.len()
    );
    let mut stale = Vec::new();
    for relative in files {
        if REFUSES_THEM.contains(&relative.as_str()) {
            continue;
        }
        let path = application.join(&relative);
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            // Listed and deleted, and the deletion not yet staged.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => panic!("{} could not be read: {error}", path.display()),
        };
        // A file that is not text (an image, a font) names no identifier a person wrote.
        let Ok(text) = String::from_utf8(bytes) else {
            continue;
        };
        for (number, line) in text.lines().enumerate() {
            let retired = line.contains("to.kala.companion") || line.contains("JT6GW3W9W6");
            let misplaced =
                line.contains(KEPT_NAMESPACE) && !may_hold_the_namespace(&relative, line);
            if retired || misplaced {
                stale.push(format!("{relative}:{}: {}", number + 1, line.trim()));
            }
        }
    }
    assert!(
        stale.is_empty(),
        "these lines name an identifier or a team the application no longer has:\n{}",
        stale.join("\n")
    );
}
