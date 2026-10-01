//
//  The device checks' own support: reading what a test asked for and building the keychain
//  queries it cleans up with. Compiled into debug builds only.
//

#if DEBUG
import Security
import XCTest

final class ProbeSupportTests: XCTestCase {
    func testTheModeIsTheWordAfterItsFlag() {
        XCTAssertEqual(ProbeArguments.mode(from: ["app", "-KRDeviceProbe", "count"]), .count)
        XCTAssertEqual(ProbeArguments.mode(from: ["app", "-KRDeviceProbe", "push-read", "-other"]), .pushRead)
        XCTAssertEqual(ProbeArguments.mode(from: ["app", "-KRDeviceProbe", "sweep"]), .sweep)
    }

    func testNoFlagAnUnknownModeAndAFlagWithNothingAfterItAreNoMode() {
        XCTAssertNil(ProbeArguments.mode(from: ["app"]))
        XCTAssertNil(ProbeArguments.mode(from: ["app", "-KRDeviceProbe", "nonsense"]))
        XCTAssertNil(ProbeArguments.mode(from: ["app", "-KRDeviceProbe"]))
    }

    func testTheColourModeIsTheWordAfterItsFlag() {
        XCTAssertEqual(ProbeArguments.colourMode(from: ["app", "-KRColourMode", "dark"]), .dark)
        XCTAssertNil(ProbeArguments.colourMode(from: ["app", "-KRColourMode", "plaid"]))
        XCTAssertNil(ProbeArguments.colourMode(from: ["app"]))
    }

    func testACountReadsAttributesAndNeverAValue() {
        let queries = KeychainSweepPlan(groups: ["TEAM.to.kala.reach", "TEAM.to.kala.reach.shared"]).countQueries()
        XCTAssertEqual(queries.count, 10, "five item classes in each of two groups")
        for each in queries {
            XCTAssertNil(each.query[kSecReturnData as String], "a count never reads a value")
            XCTAssertEqual(each.query[kSecReturnAttributes as String] as? Bool, true)
            XCTAssertEqual(each.query[kSecMatchLimit as String] as? String, kSecMatchLimitAll as String)
            XCTAssertEqual(each.query[kSecAttrSynchronizable as String] as? String, kSecAttrSynchronizableAny as String)
            XCTAssertEqual(each.query[kSecAttrAccessGroup as String] as? String, each.group)
        }
    }

    func testEveryItemClassIsCountedAndSweptInEveryGroup() {
        let plan = KeychainSweepPlan(groups: ["A", "B"])
        let classes: Set<String> = [
            kSecClassGenericPassword as String, kSecClassInternetPassword as String,
            kSecClassCertificate as String, kSecClassKey as String, kSecClassIdentity as String,
        ]
        for group in ["A", "B"] {
            let counted = Set(plan.countQueries().filter { $0.group == group }.map { $0.query[kSecClass as String] as! String })
            let swept = Set(plan.deleteQueries().filter { $0.group == group }.map { $0.query[kSecClass as String] as! String })
            XCTAssertEqual(counted, classes)
            XCTAssertEqual(swept, classes)
        }
    }

    func testASweepNamesItsGroupAndAsksForNothingBack() {
        for each in KeychainSweepPlan(groups: ["A"]).deleteQueries() {
            XCTAssertEqual(each.query[kSecAttrAccessGroup as String] as? String, "A")
            XCTAssertEqual(each.query[kSecAttrSynchronizable as String] as? String, kSecAttrSynchronizableAny as String)
            XCTAssertNil(each.query[kSecReturnData as String])
            XCTAssertNil(each.query[kSecReturnAttributes as String])
        }
    }

    func testTheFixtureIsDerivedFromTheNonceAndFromNothingElse() {
        let one = ProbeFixture.recipientKeyID(nonce: "nonce-1")
        XCTAssertEqual(one.count, 32, "an account is a 32-byte key identifier, as the extension looks one up")
        XCTAssertEqual(one, ProbeFixture.recipientKeyID(nonce: "nonce-1"))
        XCTAssertNotEqual(one, ProbeFixture.recipientKeyID(nonce: "nonce-2"))
        XCTAssertEqual(ProbeFixture.account(nonce: "nonce-1"), one.base64EncodedString())
        XCTAssertNotEqual(ProbeFixture.value(nonce: "nonce-1"), ProbeFixture.value(nonce: "nonce-2"))
        XCTAssertNotEqual(ProbeFixture.value(nonce: "nonce-1"), one, "the value is not the identifier")
    }

    func testAReportReadsBackAsOneLinePerFact() {
        var report = ProbeReport()
        report.set("status", "ok")
        report.set("count", "0")
        report.set("status", "done")
        XCTAssertEqual(report.text, "count=0\nstatus=done")
    }

    // MARK: What a keychain answer means for a count

    func testAnItemNotFoundIsAnEmptyGroupAndNothingElseIs() {
        XCTAssertEqual(KeychainAnswer.counted(status: errSecItemNotFound, found: 0), .found(0))
        XCTAssertEqual(KeychainAnswer.counted(status: errSecSuccess, found: 3), .found(3))
        for status in [errSecMissingEntitlement, errSecParam, errSecInteractionNotAllowed, errSecAuthFailed, -1] {
            XCTAssertEqual(KeychainAnswer.counted(status: status, found: 0), .failed(status), "status \(status)")
        }
    }

    func testASweepIsCleanOnlyWhenEveryDeleteSucceededOrFoundNothing() {
        XCTAssertTrue(KeychainAnswer.deleteLeftNothing(status: errSecSuccess))
        XCTAssertTrue(KeychainAnswer.deleteLeftNothing(status: errSecItemNotFound))
        XCTAssertFalse(KeychainAnswer.deleteLeftNothing(status: errSecMissingEntitlement))
        XCTAssertFalse(KeychainAnswer.deleteLeftNothing(status: errSecInteractionNotAllowed))
    }

    func testBothGroupsAreRequiredForACount() {
        XCTAssertEqual(KeychainAnswer.groupsToCount(shared: "A", private: "B"), ["A", "B"])
        XCTAssertNil(KeychainAnswer.groupsToCount(shared: nil, private: "B"))
        XCTAssertNil(KeychainAnswer.groupsToCount(shared: "A", private: nil))
        XCTAssertNil(KeychainAnswer.groupsToCount(shared: nil, private: nil))
    }

    // MARK: Which delivered notification belongs to the send being read

    private func marked(_ nonce: String?) -> [AnyHashable: Any] {
        var info: [AnyHashable: Any] = ["aps": ["alert": "x"]]
        if let nonce { info["kr_probe_nonce"] = nonce }
        return info
    }

    func testOnlyANotificationWithTheNonceOfThisSendCounts() {
        let sorted = DeliveredMarks.sort([marked("old"), marked("current"), marked(nil), marked("older")], nonce: "current")
        XCTAssertEqual(sorted.matching.count, 1)
        XCTAssertEqual(sorted.matching.first?["kr_probe_nonce"] as? String, "current")
        XCTAssertEqual(sorted.otherMarked, 2, "an earlier send's is reported and does not count")
    }

    func testWithNoNonceForThisSendNothingMatches() {
        let sorted = DeliveredMarks.sort([marked("old"), marked(nil)], nonce: nil)
        XCTAssertEqual(sorted.matching.count, 0)
        XCTAssertEqual(sorted.otherMarked, 1)
    }

    func testANoteThatIsNotAStringIsNotAMatch() {
        var odd: [AnyHashable: Any] = [:]
        odd["kr_probe_nonce"] = 7
        let sorted = DeliveredMarks.sort([odd], nonce: "7")
        XCTAssertEqual(sorted.matching.count, 0)
    }
}
#endif
