//
//  When the APNs token goes to Firebase, and what that lets a check ask for.
//
//  The system gives this device an APNs token, and Firebase makes a registration token from it. A
//  registration token is for one APNs token: it can be asked for only once Firebase has been given
//  the current one, so none made earlier is ever used. And Firebase makes an installation and a
//  registration token of its own from the APNs token it is given, which is for a person who has
//  agreed to notifications: registering for a token needs no agreement, so the token can arrive
//  first, and waits.
//

import XCTest

final class PushRegistrationTests: XCTestCase {
    private let apnsToken = Data([0x0a, 0x1b, 0x2c, 0x3d])

    private func registration(collecting given: Box<[Data]>) -> PushRegistration {
        let registration = PushRegistration()
        registration.onTokenUsable = { given.value.append($0) }
        return registration
    }

    func testTheAPNsTokenWaitsForThePersonsAgreement() {
        let given = Box<[Data]>([])
        let registration = registration(collecting: given)
        registration.registered(deviceToken: apnsToken)
        XCTAssertEqual(given.value, [], "a token with no answer to the permission is held")
        registration.permissionKnown(.granted)
        XCTAssertEqual(given.value, [apnsToken])
    }

    func testAnAgreementThatCameFirstGivesTheTokenWhenItArrives() {
        let given = Box<[Data]>([])
        let registration = registration(collecting: given)
        registration.permissionKnown(.granted)
        XCTAssertEqual(given.value, [])
        registration.registered(deviceToken: apnsToken)
        XCTAssertEqual(given.value, [apnsToken])
    }

    func testARefusalKeepsTheTokenFromFirebaseWhateverTheOrder() {
        let given = Box<[Data]>([])
        let refusedFirst = registration(collecting: given)
        refusedFirst.permissionKnown(.refused)
        refusedFirst.registered(deviceToken: apnsToken)
        let refusedAfter = registration(collecting: given)
        refusedAfter.registered(deviceToken: apnsToken)
        refusedAfter.permissionKnown(.refused)
        XCTAssertEqual(given.value, [])
    }

    func testATokenThatChangesWhileTheAgreementStandsIsGivenAgain() {
        let given = Box<[Data]>([])
        let registration = registration(collecting: given)
        registration.permissionKnown(.granted)
        registration.registered(deviceToken: apnsToken)
        let newer = Data([0x01, 0x02])
        registration.registered(deviceToken: newer)
        XCTAssertEqual(given.value.last, newer)
    }

    func testTheSystemRefusingToRegisterWithdrawsTheTokenFromAnyLaterAgreement() {
        let given = Box<[Data]>([])
        let registration = registration(collecting: given)
        registration.registered(deviceToken: apnsToken)
        registration.failed(with: NSError(domain: "test", code: 1))
        registration.permissionKnown(.granted)
        XCTAssertEqual(given.value, [])
    }

    func testAnAgreementTakenBackStopsLaterTokensGoingToFirebase() {
        let given = Box<[Data]>([])
        let registration = registration(collecting: given)
        registration.permissionKnown(.granted)
        registration.permissionKnown(.refused)
        registration.registered(deviceToken: apnsToken)
        XCTAssertEqual(given.value, [])
        XCTAssertEqual(registration.permission, .refused)
    }

    // MARK: What may be asked for

    func testNothingMayBeAskedForUntilFirebaseHasTheAPNsToken() {
        let given = Box<[Data]>([])
        let neither = registration(collecting: given)
        XCTAssertFalse(neither.tokenHandedToFirebase)
        let tokenOnly = registration(collecting: given)
        tokenOnly.registered(deviceToken: apnsToken)
        XCTAssertFalse(tokenOnly.tokenHandedToFirebase, "no answer to the permission yet")
        let agreementOnly = registration(collecting: given)
        agreementOnly.permissionKnown(.granted)
        XCTAssertFalse(agreementOnly.tokenHandedToFirebase, "no token yet")
    }

    func testItMayBeAskedForOnceBothAreHereInEitherOrder() {
        let given = Box<[Data]>([])
        let tokenFirst = registration(collecting: given)
        tokenFirst.registered(deviceToken: apnsToken)
        tokenFirst.permissionKnown(.granted)
        XCTAssertTrue(tokenFirst.tokenHandedToFirebase)
        let agreementFirst = registration(collecting: given)
        agreementFirst.permissionKnown(.granted)
        agreementFirst.registered(deviceToken: apnsToken)
        XCTAssertTrue(agreementFirst.tokenHandedToFirebase)
    }

    func testItIsNotHandedOverWithNowhereToHandItTo() {
        // Before Firebase is started nothing can take the token, and it has not been handed over.
        let registration = PushRegistration()
        registration.permissionKnown(.granted)
        registration.registered(deviceToken: apnsToken)
        XCTAssertFalse(registration.tokenHandedToFirebase)
    }

    func testTakingTheAgreementBackWithdrawsIt() {
        let given = Box<[Data]>([])
        let registration = registration(collecting: given)
        registration.permissionKnown(.granted)
        registration.registered(deviceToken: apnsToken)
        registration.permissionKnown(.refused)
        XCTAssertFalse(registration.tokenHandedToFirebase)
        registration.permissionKnown(.granted)
        XCTAssertTrue(registration.tokenHandedToFirebase, "and agreeing again gives it back")
    }

    func testANewAPNsTokenIsHandedOverBeforeAnythingMayBeAskedForAgain() {
        let given = Box<[Data]>([])
        let registration = registration(collecting: given)
        registration.permissionKnown(.granted)
        registration.registered(deviceToken: apnsToken)
        // The callback decides what happens at the moment of the hand-over: at that moment the new
        // token is not yet counted as handed over.
        var seenAtHandOver: Bool?
        registration.onTokenUsable = { _ in seenAtHandOver = registration.tokenHandedToFirebase }
        registration.registered(deviceToken: Data([0x01, 0x02]))
        XCTAssertEqual(seenAtHandOver, false)
        XCTAssertTrue(registration.tokenHandedToFirebase)
    }

    func testARegistrationThatFailedAndThenGivesANewTokenNeedsTheNewTokenHandedOver() {
        let given = Box<[Data]>([])
        let registration = registration(collecting: given)
        registration.permissionKnown(.granted)
        registration.registered(deviceToken: apnsToken)
        registration.failed(with: NSError(domain: "test", code: 1))
        XCTAssertFalse(registration.tokenHandedToFirebase)
        registration.registered(deviceToken: Data([0x09]))
        XCTAssertTrue(registration.tokenHandedToFirebase)
        XCTAssertEqual(given.value.last, Data([0x09]))
    }
}

/// A value a closure can write to, for a test to read.
final class Box<Value> {
    var value: Value
    init(_ value: Value) { self.value = value }
}
