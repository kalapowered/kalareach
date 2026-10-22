import XCTest

@testable import CompanionCallLink

/// The names the plugin reaches the application's notification adapter by are the fixture the
/// application's tests check its adapter against.
final class PushLinkTests: XCTestCase {
  private struct Link: Decodable {
    let `class`: String
    let shared: String
    let call: String
    let keys: [String: String]
    let commands: [String]
  }

  private func link() throws -> Link {
    let here = URL(fileURLWithPath: #filePath)
    // .../ios/Session/Tests/CompanionCallLinkTests/PushLinkTests.swift
    let fixtures = here.deletingLastPathComponent().deletingLastPathComponent()
      .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
      .appendingPathComponent("fixtures/push/link.json")
    return try JSONDecoder().decode(Link.self, from: Data(contentsOf: fixtures))
  }

  func testTheNamesAreTheFixtures() throws {
    let fixture = try link()
    XCTAssertEqual(PushLink.adapterClass, fixture.class)
    XCTAssertEqual(PushLink.sharedSelector, fixture.shared)
    XCTAssertEqual(PushLink.callSelector, fixture.call)
    XCTAssertEqual(PushLink.Key.command, fixture.keys["command"])
    XCTAssertEqual(PushLink.Key.arguments, fixture.keys["arguments"])
    XCTAssertEqual(PushLink.Key.reply, fixture.keys["reply"])
    XCTAssertEqual(PushLink.commands, fixture.commands)
  }
}

/// A stand-in for the application's adapter, found by the name the fixture gives it.
@objc(KRPushAdapter)
final class StandInPushAdapter: NSObject {
  static var received: [(String, String)] = []

  @objc(krShared) static func krShared() -> StandInPushAdapter { StandInPushAdapter() }

  @objc(krCall:) func krCall(_ request: NSDictionary) {
    let command = request[PushLink.Key.command] as? String ?? ""
    let arguments = request[PushLink.Key.arguments] as? String ?? ""
    StandInPushAdapter.received.append((command, arguments))
    let reply = unsafeBitCast(request[PushLink.Key.reply] as AnyObject, to: PushLink.Reply.self)
    reply("{\"state\":\"granted\"}" as NSString, nil, nil)
  }
}

final class PushLinkReachesAnAdapterTests: XCTestCase {
  func testARequestReachesTheAdapterAndItsAnswerComesBack() {
    var answered: String?
    let taken = PushLink.send("pushPermission", arguments: "{}") { result, _, _ in
      answered = result as String?
    }
    XCTAssertTrue(taken)
    XCTAssertEqual(answered, "{\"state\":\"granted\"}")
    XCTAssertEqual(StandInPushAdapter.received.last?.0, "pushPermission")
  }
}
