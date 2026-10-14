import XCTest

@testable import CompanionCallLink

/// The names the plugin reaches the application's call by are the fixture the application's tests
/// check its adapter against.
final class CallLinkTests: XCTestCase {
  private struct Link: Decodable {
    let `class`: String
    let shared: String
    let call: String
    let keys: [String: String]
    let commands: [String]
  }

  private func link() throws -> Link {
    let here = URL(fileURLWithPath: #filePath)
    // .../ios/Session/Tests/CompanionCallLinkTests/CallLinkTests.swift
    let fixtures = here.deletingLastPathComponent().deletingLastPathComponent()
      .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
      .appendingPathComponent("fixtures/call/link.json")
    return try JSONDecoder().decode(Link.self, from: Data(contentsOf: fixtures))
  }

  func testTheNamesAreTheFixtures() throws {
    let fixture = try link()
    XCTAssertEqual(CallLink.adapterClass, fixture.class)
    XCTAssertEqual(CallLink.sharedSelector, fixture.shared)
    XCTAssertEqual(CallLink.callSelector, fixture.call)
    XCTAssertEqual(CallLink.Key.command, fixture.keys["command"])
    XCTAssertEqual(CallLink.Key.arguments, fixture.keys["arguments"])
    XCTAssertEqual(CallLink.Key.news, fixture.keys["news"])
    XCTAssertEqual(CallLink.Key.reply, fixture.keys["reply"])
    XCTAssertEqual(CallLink.commands, fixture.commands)
  }
}

/// A stand-in for the application's adapter, found by the name the fixture gives it.
@objc(KRCallAdapter)
final class StandInAdapter: NSObject {
  static var received: [(String, String, Bool)] = []

  @objc(krShared) static func krShared() -> StandInAdapter { StandInAdapter() }

  @objc(krCall:) func krCall(_ request: NSDictionary) {
    let command = request[CallLink.Key.command] as? String ?? ""
    let arguments = request[CallLink.Key.arguments] as? String ?? ""
    StandInAdapter.received.append((command, arguments, request[CallLink.Key.news] != nil))
    let reply = unsafeBitCast(request[CallLink.Key.reply] as AnyObject, to: CallLink.Reply.self)
    reply("{\"done\":true}" as NSString, nil, nil)
  }
}

final class CallLinkReachesAnAdapterTests: XCTestCase {
  func testARequestReachesTheAdapterAndItsAnswerComesBack() {
    var answered: String?
    let taken = CallLink.send("callState", arguments: "{}") { result, _, _ in
      answered = result as String?
    }
    XCTAssertTrue(taken)
    XCTAssertEqual(answered, "{\"done\":true}")
    XCTAssertEqual(StandInAdapter.received.last?.0, "callState")
    XCTAssertEqual(StandInAdapter.received.last?.2, false, "only the command that opens carries news")
  }
}
