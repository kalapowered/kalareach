//
//  Giving an application's delegate the two methods the system calls with an APNs token.
//
//  The application's delegate belongs to the windowing library, and Firebase's own hook into it is
//  switched off because that hook wraps methods that have nothing to do with push. So the two
//  methods are added to the delegate's class at run time. The class is shared by every instance and
//  is somebody else's: a method it already answers, its own or one it inherits, is theirs, and
//  adding over it would take the token from them. Then neither is added, so the delegate is either
//  given both or left exactly as it was, and the caller is told which were taken.
//

import Foundation
import ObjectiveC

enum DelegateMethods {
    /// What happened to the class.
    enum Outcome: Equatable {
        /// Both methods were added.
        case added
        /// The class already answered these, so nothing was added.
        case alreadyAnswered([Selector])
    }

    static let received = Selector(("application:didRegisterForRemoteNotificationsWithDeviceToken:"))
    static let refused = Selector(("application:didFailToRegisterForRemoteNotificationsWithError:"))

    /// Adds both methods to `delegateClass`, or neither.
    static func install(
        on delegateClass: AnyClass,
        received onToken: @escaping (Data) -> Void,
        refused onRefusal: @escaping (NSError) -> Void
    ) -> Outcome {
        // `class_getInstanceMethod` looks through the superclasses; `class_addMethod` alone would
        // add one that overrides what the class inherits.
        let taken = [received, refused].filter { class_getInstanceMethod(delegateClass, $0) != nil }
        guard taken.isEmpty else { return .alreadyAnswered(taken) }

        let receivedBlock: @convention(block) (AnyObject, AnyObject, NSData) -> Void = { _, _, token in
            onToken(token as Data)
        }
        let refusedBlock: @convention(block) (AnyObject, AnyObject, NSError) -> Void = { _, _, error in
            onRefusal(error)
        }
        let first = class_addMethod(delegateClass, received, imp_implementationWithBlock(receivedBlock), "v@:@@")
        let second = class_addMethod(delegateClass, refused, imp_implementationWithBlock(refusedBlock), "v@:@@")
        // Nothing else can add between the check above and these two on the one main thread this
        // runs on; a failure here is not expected, and is reported as the methods being taken.
        if first && second { return .added }
        return .alreadyAnswered([received, refused].enumerated().compactMap { index, selector in
            (index == 0 ? !first : !second) ? selector : nil
        })
    }
}
