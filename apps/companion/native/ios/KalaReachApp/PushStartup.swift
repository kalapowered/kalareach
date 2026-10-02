//
//  Carrying out what the launch plan says about push.
//
//  Firebase's own hook into the application delegate is switched off in the build, because the
//  delegate belongs to the windowing library and Firebase would wrap methods of it that have
//  nothing to do with push, among them the ones that receive the sign-in's callback address. So the
//  two methods the system calls with an APNs token are given to the delegate here, once, before the
//  application registers. The token they receive is recorded, and is handed to Firebase once the
//  person has agreed to notifications: Firebase makes an installation and a registration token of
//  its own from it, and that is not for a person who has not agreed.
//

import FirebaseCore
import FirebaseMessaging
import Foundation
import ObjectiveC
import UIKit

/// Starts push as the launch plan says.
enum PushStartup {
    /// Why Firebase was left alone, when it was: a device check reports it.
    private(set) static var skippedBecause: String?

    /// Does each action in order.
    static func carryOut(_ plan: [LaunchAction]) {
        for action in plan {
            switch action {
            case .runDebugMode(let mode):
                #if DEBUG
                DeviceProbe.run(mode)
                #endif
                _ = mode
            case .skipFirebase(let reason):
                skippedBecause = reason
                NSLog("KalaReach: Firebase skipped, %@", reason)
            case .configureFirebase:
                FirebaseApp.configure()
                PushRegistration.shared.onTokenUsable = { Messaging.messaging().apnsToken = $0 }
            case .addTokenMethods:
                let added = installTokenMethods()
                NSLog(
                    added
                        ? "KalaReach: the application delegate now receives APNs tokens"
                        : "KalaReach: the application delegate already answers for APNs tokens, so none reaches Firebase"
                )
                #if DEBUG
                ProbeSurface.shared.show("tokenmethods", added ? "added" : "refused")
                #endif
            case .registerForRemoteNotifications:
                UIApplication.shared.registerForRemoteNotifications()
            case .setAutoInit(let on):
                Messaging.messaging().isAutoInitEnabled = on
            }
        }
    }

    /// The delegate, held for the life of the process.
    ///
    /// The application's delegate property does not keep its delegate alive, and the windowing
    /// library keeps none of its own: the system makes the delegate when the process starts. Setting
    /// the property to nil and back, as `installTokenMethods` does, must not be the moment the last
    /// reference ends.
    private static var heldDelegate: UIApplicationDelegate?

    /// Gives the delegate's class the two methods the system calls with an APNs token or a refusal.
    ///
    /// The class is read from the delegate itself rather than named, because the windowing library
    /// declares its delegate at run time. Both are added or neither is: a method the class already
    /// answers is somebody else's, and replacing it would take the token from them. The delegate is
    /// set again afterwards because the system remembers which of these methods it answers.
    private static func installTokenMethods() -> Bool {
        guard let delegate = UIApplication.shared.delegate, let delegateClass = object_getClass(delegate) else {
            return false
        }
        heldDelegate = delegate
        let outcome = DelegateMethods.install(
            on: delegateClass,
            received: { token in
                NSLog("KalaReach: the system gave this device an APNs token of %ld bytes", token.count)
                PushRegistration.shared.registered(deviceToken: token)
            },
            refused: { error in
                NSLog("KalaReach: the system would not register this device for notifications (%ld)", error.code)
                PushRegistration.shared.failed(with: error)
            }
        )
        guard outcome == .added else { return false }
        UIApplication.shared.delegate = nil
        UIApplication.shared.delegate = delegate
        return true
    }
}
