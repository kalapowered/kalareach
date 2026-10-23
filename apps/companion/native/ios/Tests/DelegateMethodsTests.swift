//
//  Giving an application's delegate the three methods the system calls about push.
//
//  The delegate belongs to the windowing library and Firebase's own hook into it is off, so the
//  methods are added to the delegate's class at run time. A method the class already answers,
//  whether its own or one it inherits, is somebody else's: adding over it would take the message
//  from them, so then none is added and the caller is told which are taken.
//

import UIKit
import XCTest

/// A delegate that answers none of the methods.
private final class BareDelegate: NSObject {}

/// A second delegate that answers none, for a test that cannot share the first one: the methods an
/// installation adds stay on the class for the life of the process.
private final class FreshDelegate: NSObject {}

/// A delegate that answers one of them itself.
private final class OneAnsweredDelegate: NSObject {
    var ownReceived = 0
    @objc(application:didRegisterForRemoteNotificationsWithDeviceToken:)
    func registered(_ application: AnyObject, token: NSData) { ownReceived += 1 }
}

/// A delegate that inherits the other one.
private class AnswersRefusal: NSObject {
    @objc(application:didFailToRegisterForRemoteNotificationsWithError:)
    func failed(_ application: AnyObject, error: NSError) {}
}
private final class InheritsRefusal: AnswersRefusal {}

/// A delegate that answers both.
private final class AnswersBoth: NSObject {
    @objc(application:didRegisterForRemoteNotificationsWithDeviceToken:)
    func registered(_ application: AnyObject, token: NSData) {}
    @objc(application:didFailToRegisterForRemoteNotificationsWithError:)
    func failed(_ application: AnyObject, error: NSError) {}
}

final class DelegateMethodsTests: XCTestCase {
    private let received = Selector(("application:didRegisterForRemoteNotificationsWithDeviceToken:"))
    private let refused = Selector(("application:didFailToRegisterForRemoteNotificationsWithError:"))
    private let remote = Selector(("application:didReceiveRemoteNotification:fetchCompletionHandler:"))

    func testAllThreeMethodsAreAddedToAClassThatAnswersNone() {
        let tokens = Box<[Data]>([])
        let errors = Box<[NSError]>([])
        let messages = Box<[[AnyHashable: Any]]>([])
        let outcome = DelegateMethods.install(
            on: BareDelegate.self,
            received: { tokens.value.append($0) },
            refused: { errors.value.append($0) },
            remote: { userInfo, finished in
                messages.value.append(userInfo)
                finished()
            }
        )
        XCTAssertEqual(outcome, .added)
        let delegate = BareDelegate()
        XCTAssertTrue(delegate.responds(to: received))
        XCTAssertTrue(delegate.responds(to: refused))
        XCTAssertTrue(delegate.responds(to: remote))

        _ = delegate.perform(received, with: NSObject(), with: Data([0x0a, 0x0b]) as NSData)
        XCTAssertEqual(tokens.value, [Data([0x0a, 0x0b])])
        _ = delegate.perform(refused, with: NSObject(), with: NSError(domain: "apns", code: 3000))
        XCTAssertEqual(errors.value.map(\.code), [3000])
    }

    /// The system waits for the result of a push that woke the application, and the message reaches
    /// the handler with the result as the system's own "new data" once the handler says it is done.
    func testAPushThatWokeTheApplicationIsHandedOnAndTheSystemIsToldWhenItIsDone() {
        let messages = Box<[String]>([])
        let results = Box<[UInt]>([])
        let finishing = Box<(() -> Void)?>(nil)
        let outcome = DelegateMethods.install(
            on: FreshDelegate.self,
            received: { _ in },
            refused: { _ in },
            remote: { (userInfo: [AnyHashable: Any], finished: @escaping () -> Void) in
                messages.value.append(userInfo["kr_challenge"] as? String ?? "")
                finishing.value = finished
            }
        )
        XCTAssertEqual(outcome, .added)
        // The system's call, made as it makes it: the application, the payload and a block to answer.
        typealias Call = @convention(c) (AnyObject, Selector, AnyObject, NSDictionary, @escaping @convention(block) (UInt) -> Void) -> Void
        let delegate = FreshDelegate()
        let implementation = delegate.method(for: remote)
        let call = unsafeBitCast(implementation, to: Call.self)
        call(delegate, remote, NSObject(), ["kr_challenge": "abc"]) { results.value.append($0) }

        XCTAssertEqual(messages.value, ["abc"])
        XCTAssertEqual(results.value, [], "the system is not answered before the handler is done")
        finishing.value?()
        XCTAssertEqual(results.value, [UIBackgroundFetchResult.newData.rawValue], "and is then told there was new data")
    }

    func testAClassThatAnswersOneItselfGetsNeitherAndKeepsItsOwn() {
        let tokens = Box<[Data]>([])
        let outcome = DelegateMethods.install(
            on: OneAnsweredDelegate.self,
            received: { tokens.value.append($0) },
            refused: { _ in },
            remote: { _, _ in }
        )
        XCTAssertEqual(outcome, .alreadyAnswered([received]))
        let delegate = OneAnsweredDelegate()
        XCTAssertFalse(delegate.responds(to: refused), "the other methods were not added either")
        XCTAssertFalse(delegate.responds(to: remote))
        _ = delegate.perform(received, with: NSObject(), with: Data([0x01]) as NSData)
        XCTAssertEqual(delegate.ownReceived, 1, "its own method still answers")
        XCTAssertEqual(tokens.value, [], "and the token did not go to ours")
    }

    func testAClassThatInheritsOneGetsNeither() {
        let outcome = DelegateMethods.install(
            on: InheritsRefusal.self, received: { _ in }, refused: { _ in }, remote: { _, _ in })
        XCTAssertEqual(outcome, .alreadyAnswered([refused]))
        XCTAssertFalse(InheritsRefusal().responds(to: received), "the other methods were not added either")
        XCTAssertFalse(InheritsRefusal().responds(to: remote))
    }

    func testAClassThatAnswersTwoNamesBothAndTakesNoThird() {
        let outcome = DelegateMethods.install(
            on: AnswersBoth.self, received: { _ in }, refused: { _ in }, remote: { _, _ in })
        XCTAssertEqual(outcome, .alreadyAnswered([received, refused]))
        XCTAssertFalse(AnswersBoth().responds(to: remote), "the third was not added beside theirs")
    }
}
