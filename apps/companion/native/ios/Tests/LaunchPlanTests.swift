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
    private let everyAuthorisation: [PushAuthorisation] = [.notDetermined, .denied, .authorised]

    func testALaunchWithConfigurationStartsPushWithoutAskingForAnything() {
        for authorisation in everyAuthorisation {
            let plan = LaunchPlan.decide(
                debugMode: nil,
                hasFirebaseConfiguration: true,
                authorisation: authorisation
            )
            XCTAssertEqual(
                plan,
                [
                    .configureFirebase,
                    .addTokenMethods,
                    .registerForRemoteNotifications,
                    .setAutoInit(authorisation == .authorised),
                ],
                "authorisation \(authorisation)"
            )
        }
    }

    func testRegistrationForRemoteNotificationsNeedsNoPermission() {
        // Registering shows no prompt, so it happens at every launch whatever the person answered.
        for authorisation in everyAuthorisation {
            let plan = LaunchPlan.decide(debugMode: nil, hasFirebaseConfiguration: true, authorisation: authorisation)
            XCTAssertTrue(plan.contains(.registerForRemoteNotifications), "authorisation \(authorisation)")
        }
    }

    func testAutoInitFollowsTheCurrentAuthorisationEveryLaunch() {
        // The setting persists across launches, so a launch that stays silent on it would keep an
        // answer the person has since taken back.
        let granted = LaunchPlan.decide(debugMode: nil, hasFirebaseConfiguration: true, authorisation: .authorised)
        let revoked = LaunchPlan.decide(debugMode: nil, hasFirebaseConfiguration: true, authorisation: .denied)
        XCTAssertTrue(granted.contains(.setAutoInit(true)))
        XCTAssertTrue(revoked.contains(.setAutoInit(false)))
    }

    func testABuildWithoutConfigurationLeavesFirebaseAlone() {
        for authorisation in everyAuthorisation {
            let plan = LaunchPlan.decide(debugMode: nil, hasFirebaseConfiguration: false, authorisation: authorisation)
            XCTAssertEqual(plan, [.skipFirebase], "authorisation \(authorisation)")
        }
    }

    func testTheCountAndSweepModesRunBeforeAnythingCanWriteAndNothingElseRuns() {
        for mode in ["count", "sweep"] {
            for configured in [true, false] {
                for authorisation in everyAuthorisation {
                    let plan = LaunchPlan.decide(
                        debugMode: mode,
                        hasFirebaseConfiguration: configured,
                        authorisation: authorisation
                    )
                    XCTAssertEqual(plan, [.runDebugMode(mode)], "\(mode) \(configured) \(authorisation)")
                }
            }
        }
    }

    func testAnotherModeRunsAfterPushHasStarted() {
        let configured = LaunchPlan.decide(debugMode: "push", hasFirebaseConfiguration: true, authorisation: .denied)
        XCTAssertEqual(configured.last, .runDebugMode("push"))
        XCTAssertEqual(configured.first, .configureFirebase)
        let bare = LaunchPlan.decide(debugMode: "keychain", hasFirebaseConfiguration: false, authorisation: .denied)
        XCTAssertEqual(bare, [.skipFirebase, .runDebugMode("keychain")])
    }

    func testNoPlanEverAsksForAPermission() {
        // The actions have no case that does, so this holds by construction; this keeps it so.
        let modes: [String?] = [nil, "count", "sweep", "keychain", "push", "push-read", "audio", "shots"]
        for mode in modes {
            for configured in [true, false] {
                for authorisation in everyAuthorisation {
                    let plan = LaunchPlan.decide(debugMode: mode, hasFirebaseConfiguration: configured, authorisation: authorisation)
                    for action in plan {
                        XCTAssertFalse("\(action)".lowercased().contains("authoris") && !"\(action)".contains("setAutoInit"), "\(action)")
                    }
                }
            }
        }
    }
}
