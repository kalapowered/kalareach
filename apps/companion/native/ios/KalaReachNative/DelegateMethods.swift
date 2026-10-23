//
//  Giving an application's delegate the three methods the system calls about push.
//
//  The application's delegate belongs to the windowing library, and Firebase's own hook into it is
//  switched off because that hook wraps methods that have nothing to do with push. So the methods
//  are added to the delegate's class at run time: the two the system calls with an APNs token or
//  its refusal, and the one it calls when a push with content wakes the application in the
//  background, which is how a registration challenge arrives. The class is shared by every instance
//  and is somebody else's: a method it already answers, its own or one it inherits, is theirs, and
//  adding over it would take the message from them. Then none is added, so the delegate is either
//  given all three or left exactly as it was, and the caller is told which were taken.
//

import Foundation
import UIKit
import ObjectiveC

enum DelegateMethods {
    /// What happened to the class.
    enum Outcome: Equatable {
        /// All three methods were added.
        case added
        /// The class already answered these, so nothing was added.
        case alreadyAnswered([Selector])
    }

    static let received = Selector(("application:didRegisterForRemoteNotificationsWithDeviceToken:"))
    static let refused = Selector(("application:didFailToRegisterForRemoteNotificationsWithError:"))
    static let remote = Selector(("application:didReceiveRemoteNotification:fetchCompletionHandler:"))

    /// What the system waits for after a push that woke the application: the result, within about
    /// thirty seconds.
    typealias Finished = @convention(block) (UInt) -> Void

    /// Adds all three methods to `delegateClass`, or none.
    static func install(
        on delegateClass: AnyClass,
        received onToken: @escaping (Data) -> Void,
        refused onRefusal: @escaping (NSError) -> Void,
        remote onMessage: @escaping ([AnyHashable: Any], @escaping () -> Void) -> Void
    ) -> Outcome {
        // `class_getInstanceMethod` looks through the superclasses; `class_addMethod` alone would
        // add one that overrides what the class inherits.
        let all = [received, refused, remote]
        let taken = all.filter { class_getInstanceMethod(delegateClass, $0) != nil }
        guard taken.isEmpty else { return .alreadyAnswered(taken) }

        let receivedBlock: @convention(block) (AnyObject, AnyObject, NSData) -> Void = { _, _, token in
            onToken(token as Data)
        }
        let refusedBlock: @convention(block) (AnyObject, AnyObject, NSError) -> Void = { _, _, error in
            onRefusal(error)
        }
        let remoteBlock: @convention(block) (AnyObject, AnyObject, NSDictionary, @escaping Finished) -> Void = {
            _, _, userInfo, finished in
            // The system is told there was new data: the application did what the message asked.
            onMessage(userInfo as? [AnyHashable: Any] ?? [:]) { finished(UIBackgroundFetchResult.newData.rawValue) }
        }
        let added = [
            class_addMethod(delegateClass, received, imp_implementationWithBlock(receivedBlock), "v@:@@"),
            class_addMethod(delegateClass, refused, imp_implementationWithBlock(refusedBlock), "v@:@@"),
            class_addMethod(delegateClass, remote, imp_implementationWithBlock(remoteBlock), "v@:@@@?"),
        ]
        // Nothing else can add between the check above and these on the one main thread this runs
        // on; a failure here is not expected, and is reported as the methods being taken.
        if !added.contains(false) { return .added }
        return .alreadyAnswered(all.enumerated().compactMap { index, selector in added[index] ? nil : selector })
    }
}
