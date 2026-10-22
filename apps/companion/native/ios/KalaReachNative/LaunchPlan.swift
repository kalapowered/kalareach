//
//  What the application does about push when it starts.
//
//  The decision is made from facts and nothing else, so the rules can be held by tests rather than
//  by whoever last read the launch code. Four of them matter. A build with no Firebase
//  configuration, or one Firebase would end the application over, does not start Firebase, because
//  starting it with nothing to start from stops the process. A launch never asks the person for a permission: the product asks in its own context,
//  where the person can see why, and registering for remote notifications needs no permission at
//  all. The two modes that look at or clean out the device's keychain run before anything else
//  has had a chance to write to it. And whatever Firebase does, the application's delegate is given
//  the methods a push reaches it by and the notification centre a delegate that hears a tap, because
//  a registration challenge and a tap on a notification do not depend on Firebase being started.
//

import Foundation
import UserNotifications

/// One thing a launch does.
enum LaunchAction: Equatable {
    /// A device check's own mode, which a debug build was started with.
    case runDebugMode(String)
    /// Firebase is left alone, for the reason given: this build has no configuration, or has one
    /// Firebase would end the application over.
    case skipFirebase(String)
    /// Reads the configuration and starts Firebase.
    case configureFirebase
    /// Gives the application's delegate the three methods the system calls about push: with an APNs
    /// token, with its refusal, and when a push woke the application.
    case addDelegateMethods
    /// Makes the notification centre's delegate the one that hears a tap on a notification.
    case hearNotificationTaps
    /// Asks the system for an APNs token, which shows the person nothing.
    case registerForRemoteNotifications
    /// Lets Firebase generate a registration token on its own, or not, as the permission stands.
    case setAutoInit(Bool)
}

/// The launch, decided.
enum LaunchPlan {
    /// The modes that run before Firebase starts and stop the launch there.
    private static let beforeAnythingWrites: Set<String> = ["count", "sweep"]

    /// What a launch does, in order.
    static func decide(
        debugMode: String?,
        firebase: FirebaseConfiguration,
        permission: PushPermission
    ) -> [LaunchAction] {
        if let mode = debugMode, beforeAnythingWrites.contains(mode) {
            return [.runDebugMode(mode)]
        }
        var plan: [LaunchAction]
        switch firebase {
        case .usable:
            plan = [
                .configureFirebase,
                .addDelegateMethods,
                .hearNotificationTaps,
                .registerForRemoteNotifications,
                .setAutoInit(permission == .granted),
            ]
        case .unusable(let reason):
            plan = [.skipFirebase(reason), .addDelegateMethods, .hearNotificationTaps]
        }
        if let mode = debugMode {
            plan.append(.runDebugMode(mode))
        }
        return plan
    }
}

extension PushPermission {
    /// What the system's notification setting says about the person's answer.
    ///
    /// Read without asking: a provisional or ephemeral grant is a yes, and a setting this code does
    /// not know is no answer yet, which waits rather than agrees.
    init(status: UNAuthorizationStatus) {
        switch status {
        case .authorized, .provisional, .ephemeral: self = .granted
        case .denied: self = .refused
        case .notDetermined: self = .unknown
        @unknown default: self = .unknown
        }
    }
}
