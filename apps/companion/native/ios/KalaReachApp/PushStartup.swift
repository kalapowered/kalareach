//
//  Carrying out what the launch plan says about push.
//
//  Firebase's own hook into the application delegate is switched off in the build, because the
//  delegate belongs to the windowing library and Firebase would wrap methods of it that have
//  nothing to do with push, among them the ones that receive the sign-in's callback address. So the
//  methods the system calls about push are given to the delegate here, once, before the application
//  registers: the two it calls with an APNs token or its refusal, and the one it calls when a push
//  woke the application, which is how a registration challenge arrives (`PushChallenge`). The token
//  is recorded, and is handed to Firebase once the person has agreed to notifications: Firebase
//  makes an installation and a registration token of its own from it, and that is not for a person
//  who has not agreed. The registration token Firebase gives is kept where the platform plugin reads
//  it, and the application compares it with what each host registered with.
//

import FirebaseCore
import FirebaseMessaging
import Foundation
import ObjectiveC
import UIKit
import UserNotifications

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
                PushRegistration.shared.onTokenUsable = { apns in
                    Messaging.messaging().apnsToken = apns
                    // The person has agreed and Firebase has the APNs token, so it may make this
                    // installation's registration token now, which it did not before. It arrives at
                    // the delegate below and is kept; asking for it as well makes it come at once.
                    Messaging.messaging().isAutoInitEnabled = true
                    Messaging.messaging().token { token, _ in
                        if let token { PushTokenStore().given(token) }
                    }
                }
                Messaging.messaging().delegate = PushTokens.shared
                Messaging.messaging().token { token, _ in
                    if let token { PushTokenStore().given(token) }
                }
            case .addDelegateMethods:
                let added = installDelegateMethods()
                NSLog(
                    added
                        ? "KalaReach: the application delegate now receives push"
                        : "KalaReach: the application delegate already answers for push, so none reaches this application"
                )
                #if DEBUG
                ProbeSurface.shared.show("tokenmethods", added ? "added" : "refused")
                PushDeviceRun.listen()
                #endif
            case .hearNotificationTaps:
                UNUserNotificationCenter.current().delegate = NotificationRouter.shared
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
    /// the property to nil and back, as `installDelegateMethods` does, must not be the moment the last
    /// reference ends.
    private static var heldDelegate: UIApplicationDelegate?

    /// Gives the delegate's class the three methods the system calls about push.
    ///
    /// The class is read from the delegate itself rather than named, because the windowing library
    /// declares its delegate at run time. All are added or none is: a method the class already
    /// answers is somebody else's, and replacing it would take the message from them. The delegate is
    /// set again afterwards because the system remembers which of these methods it answers.
    private static func installDelegateMethods() -> Bool {
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
            },
            remote: { userInfo, finished in
                PushChallenge.shared.received(userInfo: userInfo, finished: finished)
            }
        )
        guard outcome == .added else { return false }
        UIApplication.shared.delegate = nil
        UIApplication.shared.delegate = delegate
        return true
    }
}
