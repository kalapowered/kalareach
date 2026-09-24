import CompanionSession
import XCTest

final class SessionRulesTests: XCTestCase {
  private func version(_ major: Int, _ minor: Int) -> OperatingSystemVersion {
    OperatingSystemVersion(majorVersion: major, minorVersion: minor, patchVersion: 0)
  }

  func testTheHttpsCallbackStartsAtIOS17Point4() {
    XCTAssertTrue(takesHttpsCallback(version(17, 4)))
    XCTAssertTrue(takesHttpsCallback(version(17, 10)))
    XCTAssertTrue(takesHttpsCallback(version(18, 0)))
    XCTAssertTrue(takesHttpsCallback(version(26, 5)))
    XCTAssertFalse(takesHttpsCallback(version(17, 3)))
    XCTAssertFalse(takesHttpsCallback(version(17, 0)))
    XCTAssertFalse(takesHttpsCallback(version(16, 7)))
  }

  func testTheAttemptsModeChoosesTheCallbackAndEverySessionIsEphemeral() {
    let https = sessionConfiguration(
      mode: "sessionHttps", httpsHost: "reach.kala.to", httpsPath: "/app/oauth/callback",
      scheme: "to.kala.reach", httpsTaken: true)
    XCTAssertEqual(https?.callback, .https(host: "reach.kala.to", path: "/app/oauth/callback"))
    XCTAssertEqual(https?.ephemeral, true)

    let scheme = sessionConfiguration(
      mode: "sessionScheme", httpsHost: "reach.kala.to", httpsPath: "/app/oauth/callback",
      scheme: "to.kala.reach", httpsTaken: false)
    XCTAssertEqual(scheme?.callback, .scheme("to.kala.reach"))
    XCTAssertEqual(scheme?.ephemeral, true)

    // An attempt that asked for the HTTPS callback on a system without one is refused rather
    // than sent a session whose answer could never come back.
    XCTAssertNil(
      sessionConfiguration(
        mode: "sessionHttps", httpsHost: "reach.kala.to", httpsPath: "/app/oauth/callback",
        scheme: "to.kala.reach", httpsTaken: false))
    XCTAssertNil(
      sessionConfiguration(
        mode: "authTab", httpsHost: "reach.kala.to", httpsPath: "/app/oauth/callback",
        scheme: "to.kala.reach", httpsTaken: true))
  }

  func testEachAttemptIsAnsweredOnceAndALateCompletionIsToldApart() {
    let attempts = SessionAttempts()
    XCTAssertNil(attempts.begin("1"))
    XCTAssertEqual(attempts.begin("2"), "1")
    XCTAssertFalse(attempts.end("1"), "the earlier attempt's completion is late")
    XCTAssertEqual(attempts.inProgress, "2")
    XCTAssertTrue(attempts.end("2"))
    XCTAssertFalse(attempts.end("2"), "an attempt is answered once")
    XCTAssertNil(attempts.inProgress)
  }
}
