//
//  The application's native launch.
//
//  `LaunchHook.m` calls `didFinishLaunching` when the system says the application has launched. What
//  happens next is `LaunchPlan`'s decision, made from three facts: which device check a debug build
//  was started for, whether the build holds Firebase configuration, and where the person's answer to
//  the notification permission stands. This file only carries the plan out.
//

import Foundation
import UIKit
import UserNotifications

/// The entry the launch hook calls, under the name it looks up.
@objc(KRNativeLaunch)
final class KRNativeLaunch: NSObject {
    @objc static func didFinishLaunching() {
        var debugMode: String?
        #if DEBUG
        debugMode = ProbeArguments.mode(from: CommandLine.arguments)?.rawValue
        DeviceProbe.applyColourMode()
        #endif
        let configured = Bundle.main.path(forResource: "GoogleService-Info", ofType: "plist") != nil

        // The modes that look at the keychain before anything writes to it need no answer about
        // the permission, and wait for none.
        let early = LaunchPlan.decide(debugMode: debugMode, hasFirebaseConfiguration: configured, authorisation: .notDetermined)
        if let mode = debugMode, early == [.runDebugMode(mode)] {
            PushStartup.carryOut(early)
            return
        }
        UNUserNotificationCenter.current().getNotificationSettings { settings in
            let authorisation: PushAuthorisation
            switch settings.authorizationStatus {
            case .authorized, .provisional, .ephemeral: authorisation = .authorised
            case .denied: authorisation = .denied
            default: authorisation = .notDetermined
            }
            let plan = LaunchPlan.decide(debugMode: debugMode, hasFirebaseConfiguration: configured, authorisation: authorisation)
            DispatchQueue.main.async { PushStartup.carryOut(plan) }
        }
    }
}
