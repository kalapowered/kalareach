//
//  What the application does about push when it starts, decided from facts and nothing else.
//
//  The decision is a pure function so the rules can be held by tests: no build starts without
//  Firebase configuration trying to talk to Firebase, no launch asks the person for a permission
//  (the product asks in its own context), and the two modes that clean up the device's keychain
//  run before anything else has had a chance to write to it.
//

import XCTest

final class LaunchPlanTests: XCTestCase {
    private let everyPermission: [PushPermission] = [.unknown, .refused, .granted]

    func testALaunchWithConfigurationStartsPushWithoutAskingForAnything() {
        for permission in everyPermission {
            let plan = LaunchPlan.decide(
                debugMode: nil,
                hasFirebaseConfiguration: true,
                permission: permission
            )
            XCTAssertEqual(
                plan,
                [
                    .configureFirebase,
                    .addTokenMethods,
                    .registerForRemoteNotifications,
                    .setAutoInit(permission == .granted),
                ],
                "permission \(permission)"
            )
        }
    }

    func testRegistrationForRemoteNotificationsNeedsNoPermission() {
        // Registering shows no prompt, so it happens at every launch whatever the person answered.
        for permission in everyPermission {
            let plan = LaunchPlan.decide(debugMode: nil, hasFirebaseConfiguration: true, permission: permission)
            XCTAssertTrue(plan.contains(.registerForRemoteNotifications), "permission \(permission)")
        }
    }

    func testAutoInitFollowsTheCurrentPermissionEveryLaunch() {
        // The setting persists across launches, so a launch that stays silent on it would keep an
        // answer the person has since taken back.
        let granted = LaunchPlan.decide(debugMode: nil, hasFirebaseConfiguration: true, permission: .granted)
        let revoked = LaunchPlan.decide(debugMode: nil, hasFirebaseConfiguration: true, permission: .refused)
        XCTAssertTrue(granted.contains(.setAutoInit(true)))
        XCTAssertTrue(revoked.contains(.setAutoInit(false)))
    }

    func testABuildWithoutConfigurationLeavesFirebaseAlone() {
        for permission in everyPermission {
            let plan = LaunchPlan.decide(debugMode: nil, hasFirebaseConfiguration: false, permission: permission)
            XCTAssertEqual(plan, [.skipFirebase], "permission \(permission)")
        }
    }

    func testTheCountAndSweepModesRunBeforeAnythingCanWriteAndNothingElseRuns() {
        for mode in ["count", "sweep"] {
            for configured in [true, false] {
                for permission in everyPermission {
                    let plan = LaunchPlan.decide(
                        debugMode: mode,
                        hasFirebaseConfiguration: configured,
                        permission: permission
                    )
                    XCTAssertEqual(plan, [.runDebugMode(mode)], "\(mode) \(configured) \(permission)")
                }
            }
        }
    }

    func testAnotherModeRunsAfterPushHasStarted() {
        let configured = LaunchPlan.decide(debugMode: "push", hasFirebaseConfiguration: true, permission: .refused)
        XCTAssertEqual(configured.last, .runDebugMode("push"))
        XCTAssertEqual(configured.first, .configureFirebase)
        let bare = LaunchPlan.decide(debugMode: "keychain", hasFirebaseConfiguration: false, permission: .refused)
        XCTAssertEqual(bare, [.skipFirebase, .runDebugMode("keychain")])
    }

    func testNoPlanEverAsksForAPermission() {
        // The actions have no case that does, so this holds by construction; this keeps it so.
        let modes: [String?] = [nil, "count", "sweep", "keychain", "push", "push-read", "audio", "shots"]
        for mode in modes {
            for configured in [true, false] {
                for permission in everyPermission {
                    let plan = LaunchPlan.decide(debugMode: mode, hasFirebaseConfiguration: configured, permission: permission)
                    for action in plan {
                        XCTAssertFalse("\(action)".lowercased().contains("authoris") && !"\(action)".contains("setAutoInit"), "\(action)")
                    }
                }
            }
        }
    }
}
