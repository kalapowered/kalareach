//
//  Giving an application's delegate the two methods the system calls with an APNs token.
//
//  The delegate belongs to the windowing library and Firebase's own hook into it is off, so the two
//  methods are added to the delegate's class at run time. A method the class already answers,
//  whether its own or one it inherits, is somebody else's: adding over it would take the token from
//  them, so then neither is added and the caller is told which are taken.
//

import XCTest

/// A delegate that answers neither method.
private final class BareDelegate: NSObject {}

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

    func testBothMethodsAreAddedToAClassThatAnswersNeither() {
        let tokens = Box<[Data]>([])
        let errors = Box<[NSError]>([])
        let outcome = DelegateMethods.install(
            on: BareDelegate.self,
            received: { tokens.value.append($0) },
            refused: { errors.value.append($0) }
        )
        XCTAssertEqual(outcome, .added)
        let delegate = BareDelegate()
        XCTAssertTrue(delegate.responds(to: received))
        XCTAssertTrue(delegate.responds(to: refused))

        _ = delegate.perform(received, with: NSObject(), with: Data([0x0a, 0x0b]) as NSData)
        XCTAssertEqual(tokens.value, [Data([0x0a, 0x0b])])
        _ = delegate.perform(refused, with: NSObject(), with: NSError(domain: "apns", code: 3000))
        XCTAssertEqual(errors.value.map(\.code), [3000])
    }

    func testAClassThatAnswersOneItselfGetsNeitherAndKeepsItsOwn() {
        let tokens = Box<[Data]>([])
        let outcome = DelegateMethods.install(
            on: OneAnsweredDelegate.self,
            received: { tokens.value.append($0) },
            refused: { _ in }
        )
        XCTAssertEqual(outcome, .alreadyAnswered([received]))
        let delegate = OneAnsweredDelegate()
        XCTAssertFalse(delegate.responds(to: refused), "the other method was not added either")
        _ = delegate.perform(received, with: NSObject(), with: Data([0x01]) as NSData)
        XCTAssertEqual(delegate.ownReceived, 1, "its own method still answers")
        XCTAssertEqual(tokens.value, [], "and the token did not go to ours")
    }

    func testAClassThatInheritsOneGetsNeither() {
        let outcome = DelegateMethods.install(on: InheritsRefusal.self, received: { _ in }, refused: { _ in })
        XCTAssertEqual(outcome, .alreadyAnswered([refused]))
        XCTAssertFalse(InheritsRefusal().responds(to: received), "the other method was not added either")
    }

    func testAClassThatAnswersBothNamesBoth() {
        let outcome = DelegateMethods.install(on: AnswersBoth.self, received: { _ in }, refused: { _ in })
        XCTAssertEqual(outcome, .alreadyAnswered([received, refused]))
    }
}
