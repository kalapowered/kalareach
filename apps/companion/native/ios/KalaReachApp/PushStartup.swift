//
//  Carrying out what the launch plan says about push.
//
//  Firebase's own hook into the application delegate is switched off in the build, because the
//  delegate belongs to the windowing library and Firebase would wrap methods of it that have
//  nothing to do with push, among them the ones that receive the sign-in's callback address. So the
//  two methods the system calls with an APNs token are given to the delegate here, once, before the
//  application registers, and the token they receive is handed to Firebase and recorded.
//

import FirebaseCore
import FirebaseMessaging
import Foundation
import ObjectiveC
import UIKit

/// Starts push as the launch plan says.
enum PushStartup {
    /// Does each action in order.
    static func carryOut(_ plan: [LaunchAction]) {
        for action in plan {
            switch action {
            case .runDebugMode(let mode):
                #if DEBUG
                DeviceProbe.run(mode)
                #endif
                _ = mode
            case .skipFirebase:
                NSLog("KalaReach: Firebase skipped, this build holds no GoogleService-Info.plist")
            case .configureFirebase:
                FirebaseApp.configure()
                Messaging.messaging().delegate = TokenListener.shared
            case .addTokenMethods:
                if installTokenMethods() {
                    NSLog("KalaReach: the application delegate now receives APNs tokens")
                } else {
                    NSLog("KalaReach: the application delegate already answers for APNs tokens, so none reaches Firebase")
                }
            case .registerForRemoteNotifications:
                UIApplication.shared.registerForRemoteNotifications()
            case .setAutoInit(let on):
                Messaging.messaging().isAutoInitEnabled = on
            }
        }
    }

    /// Gives the delegate's class the two methods the system calls with an APNs token or a refusal.
    ///
    /// The class is read from the delegate itself rather than named, because the windowing library
    /// declares its delegate at run time. Both additions have to succeed: a method the class already
    /// answers is somebody else's, and replacing it would take the token from them. The delegate is
    /// set again afterwards because the system remembers which of these methods it answers.
    private static func installTokenMethods() -> Bool {
        guard let delegate = UIApplication.shared.delegate, let delegateClass = object_getClass(delegate) else {
            return false
        }
        let received: @convention(block) (AnyObject, UIApplication, Data) -> Void = { _, _, token in
            Messaging.messaging().apnsToken = token
            PushRegistration.shared.registered(deviceToken: token)
        }
        let refused: @convention(block) (AnyObject, UIApplication, NSError) -> Void = { _, _, error in
            PushRegistration.shared.failed(with: error)
        }
        let added = class_addMethod(
            delegateClass,
            NSSelectorFromString("application:didRegisterForRemoteNotificationsWithDeviceToken:"),
            imp_implementationWithBlock(received),
            "v@:@@"
        )
        let failed = class_addMethod(
            delegateClass,
            NSSelectorFromString("application:didFailToRegisterForRemoteNotificationsWithError:"),
            imp_implementationWithBlock(refused),
            "v@:@@"
        )
        UIApplication.shared.delegate = nil
        UIApplication.shared.delegate = delegate
        return added && failed
    }
}

/// Hears Firebase's registration token, which counts once the APNs token has been mapped.
final class TokenListener: NSObject, MessagingDelegate {
    static let shared = TokenListener()

    func messaging(_ messaging: Messaging, didReceiveRegistrationToken fcmToken: String?) {
        PushRegistration.shared.fcmTokenReceived(fcmToken)
    }
}
