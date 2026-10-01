//
//  The two tokens push needs, and the order they count in.
//
//  The system gives this device an APNs token and Firebase gives it a registration token. A
//  registration token Firebase issues before the APNs token has been mapped to it cannot be
//  delivered to, so it is held and does not count until the APNs token is there.
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
}
