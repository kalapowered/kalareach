//
//  The two tokens push needs, and the order they count in.
//
//  The system gives this device an APNs token and Firebase gives it a registration token. A
//  registration token Firebase issues before the APNs token has been mapped to it cannot be
//  delivered to, so it is held and does not count until the APNs token is there. And the APNs
//  token is given to Firebase, which makes an installation and a registration token of its own
//  from it, only once the person has agreed to notifications: registering for a token needs no
//  agreement, so the token can arrive first and waits.
//

import XCTest

final class PushRegistrationTests: XCTestCase {
    private let apnsToken = Data([0x0a, 0x1b, 0x2c, 0x3d])

    func testAFirebaseTokenDoesNotCountBeforeTheAPNsTokenIsMapped() {
        let registration = PushRegistration()
        registration.fcmTokenReceived("fcm-token-1")
        XCTAssertNil(registration.fcmToken)
    }

    func testTheHeldTokenCountsOnceTheAPNsTokenIsMapped() {
        let registration = PushRegistration()
        registration.fcmTokenReceived("fcm-token-1")
        registration.registered(deviceToken: apnsToken)
        XCTAssertEqual(registration.fcmToken, "fcm-token-1")
        XCTAssertEqual(registration.state, .registered(token: "0a1b2c3d"))
    }

    func testANewerTokenReplacesTheOneThatCounted() {
        let registration = PushRegistration()
        registration.registered(deviceToken: apnsToken)
        registration.fcmTokenReceived("fcm-token-1")
        registration.fcmTokenReceived("fcm-token-2")
        XCTAssertEqual(registration.fcmToken, "fcm-token-2")
    }

    func testANewAPNsTokenDropsTheRegistrationTokenMadeFromTheOldOne() {
        // Firebase makes a new registration token when the APNs token changes. Until it has, the old
        // one is for a device address that is gone.
        let registration = PushRegistration()
        registration.registered(deviceToken: apnsToken)
        registration.fcmTokenReceived("fcm-token-1")
        registration.registered(deviceToken: Data([0x01, 0x02]))
        XCTAssertNil(registration.fcmToken)
        registration.fcmTokenReceived("fcm-token-2")
        XCTAssertEqual(registration.fcmToken, "fcm-token-2")
    }

    func testTheSameAPNsTokenAgainKeepsTheRegistrationToken() {
        let registration = PushRegistration()
        registration.registered(deviceToken: apnsToken)
        registration.fcmTokenReceived("fcm-token-1")
        registration.registered(deviceToken: apnsToken)
        XCTAssertEqual(registration.fcmToken, "fcm-token-1")
    }

    func testTheSystemRefusingToRegisterTakesTheTokenAway() {
        let registration = PushRegistration()
        registration.registered(deviceToken: apnsToken)
        registration.fcmTokenReceived("fcm-token-1")
        registration.failed(with: NSError(domain: "test", code: 1))
        XCTAssertNil(registration.fcmToken)
    }

    func testAnEmptyTokenIsNoToken() {
        let registration = PushRegistration()
        registration.registered(deviceToken: apnsToken)
        registration.fcmTokenReceived("fcm-token-1")
        registration.fcmTokenReceived(nil)
        XCTAssertNil(registration.fcmToken)
    }

    // MARK: When the APNs token goes to Firebase

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
}

/// A value a closure can write to, for a test to read.
final class Box<Value> {
    var value: Value
    init(_ value: Value) { self.value = value }
}
