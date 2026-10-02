//
//  The keychain, on the device (26.27).
//
//  The application's two keychain groups are the only place its keys live, and what may reach each
//  is decided by the entitlements the signed build carries, which a simulator does not enforce the
//  same way. These run the application's own device checks in the signed process and decide from
//  what they report. A session starts by counting what the two groups hold, by attributes alone,
//  and goes on only if that is nothing.
//

import XCTest

final class KeychainTests: DeviceTestCase {
    /// The baseline: nothing of this application is in either group, and every query was answered.
    func testTheGroupsHoldNothingBeforeASessionStarts() throws {
        launch(probe: "count")
        let facts = try XCTUnwrap(probeFacts("count"), "the count check did not report")
        sayFacts("count", facts)
        XCTAssertEqual(facts["ok"], "1", "a query that was refused is not an empty group")
        XCTAssertEqual(facts["total"], "0", "the groups are not empty, so the session stops here")
        XCTAssertEqual(facts["groups"]?.split(separator: ",").count, 2, "both groups are counted")
    }

    /// The application files a key in each group and reads it back, and is refused a group that is
    /// not its own.
    func testTheApplicationCanUseItsOwnGroupsAndNoOtherUnderTheTeamsPrefix() throws {
        launch(probe: "keychain")
        let facts = try XCTUnwrap(probeFacts("keychain"), "the keychain check did not report")
        sayFacts("keychain", facts)
        XCTAssertEqual(facts["shared.write"], "0", "the shared group takes the preview key")
        XCTAssertEqual(facts["private.write"], "0", "the private group takes the authorisation key")
        XCTAssertEqual(facts["shared.read"], "0")
        XCTAssertEqual(facts["private.read"], "0")
        XCTAssertEqual(facts["shared.match"], "1", "what was read is what was written")
        XCTAssertEqual(facts["private.match"], "1")
        XCTAssertEqual(facts["foreign.refused"], "1", "a group the application is not entitled to refuses the write itself")
        XCTAssertEqual(facts["shared.remove"], "0", "the fixtures were removed")
        XCTAssertEqual(facts["private.remove"], "0")
    }

    /// Everything the application and Firebase wrote is removed, and the groups are empty again.
    func testASweepLeavesBothGroupsEmpty() throws {
        launch(probe: "sweep")
        let facts = try XCTUnwrap(probeFacts("sweep"), "the sweep did not report")
        sayFacts("sweep", facts)
        XCTAssertEqual(facts["ok"], "1", "a refusal or something left is not a clean sweep")
        XCTAssertEqual(facts["remaining"], "0")
    }
}
