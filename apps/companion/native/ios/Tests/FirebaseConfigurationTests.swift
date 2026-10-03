//
//  Whether a build's Firebase configuration is one Firebase can start from.
//
//  Firebase raises an exception, and the application ends at every launch, when its configuration
//  has an API key it does not accept or an application identifier it cannot read. A file that
//  would do that must be found before Firebase is asked to start, so the application runs without
//  push and says why. The control is a file that is valid: it must pass, or the check would make
//  every build one without push.
//

import XCTest

final class FirebaseConfigurationTests: XCTestCase {
    /// A key of the shape Firebase issues: "AIza" and thirty-five more characters. It is put together here so that
    /// no source file holds a string that a scan for credentials would take for a real key.
    private static let validKey = "AIza" + "SyA-0123456789abcdefghijklmnopqrstu"

    /// A configuration of the shape Firebase issues, with these values changed.
    private func plist(_ changes: [String: Any?] = [:]) -> Data {
        var values: [String: Any] = [
            "API_KEY": Self.validKey,
            "GCM_SENDER_ID": "123456789012",
            "BUNDLE_ID": "to.kala.reach",
            "PROJECT_ID": "a-project",
            "GOOGLE_APP_ID": "1:123456789012:ios:0123456789abcdef",
            "IS_GCM_ENABLED": true,
        ]
        for (key, value) in changes {
            if let value { values[key] = value } else { values.removeValue(forKey: key) }
        }
        return try! PropertyListSerialization.data(fromPropertyList: values, format: .xml, options: 0)
    }

    private func problems(_ changes: [String: Any?] = [:], bundle: String = "to.kala.reach") -> [String] {
        FirebaseConfigurationCheck.problems(in: plist(changes), bundleIdentifier: bundle)
    }

    // MARK: The control

    func testAFileOfTheShapeFirebaseIssuesPasses() {
        XCTAssertEqual(problems(), [])
    }

    func testAnApplicationIdWithTheLongHashFirebaseIssuesPasses() {
        // The hash in a real application identifier is longer than sixteen hex digits.
        XCTAssertEqual(problems(["GOOGLE_APP_ID": "1:123456789012:ios:0123456789abcdef012345"]), [])
    }

    func testAFileWithNoBundleIdentifierIsLeftToFirebase() {
        XCTAssertEqual(problems(["BUNDLE_ID": nil]), [])
    }

    func testAnApplicationIdOfAnotherKnownFormatVersionIsLeftToFirebase() {
        // Firebase permits a version it does not know, when the id is otherwise formed.
        XCTAssertEqual(problems(["GOOGLE_APP_ID": "2:whatever:ios:abc"]), [])
    }

    // MARK: What would end the application

    func testAnApiKeyOfTheWrongLengthIsFound() {
        XCTAssertTrue(problems(["API_KEY": "AIzaShort"]).contains { $0.contains("API_KEY") })
        XCTAssertTrue(problems(["API_KEY": Self.validKey + "v"]).contains { $0.contains("API_KEY") })
    }

    func testAnApiKeyThatDoesNotStartWithAnAIsFound() {
        XCTAssertTrue(problems(["API_KEY": "BIzaSyA-0123456789abcdefghijklmnopqrstu"]).contains { $0.contains("API_KEY") })
    }

    func testAnApiKeyWithACharacterOutsideTheUrlSafeSetIsFound() {
        XCTAssertTrue(problems(["API_KEY": "AIzaSyA 0123456789abcdefghijklmnopqrstu"]).contains { $0.contains("API_KEY") })
        XCTAssertTrue(problems(["API_KEY": "AIzaSyA+0123456789abcdefghijklmnopqrstu"]).contains { $0.contains("API_KEY") })
    }

    func testAnApiKeyIsMeasuredInUTF16UnitsAsFirebaseDoes() {
        // One letter outside the basic plane is one character and two units: 39 characters, 40 units.
        let key = "A" + String(repeating: "b", count: 37) + "\u{1D4D0}"
        XCTAssertEqual(key.count, 39)
        XCTAssertEqual(key.utf16.count, 40)
        XCTAssertTrue(problems(["API_KEY": key]).contains { $0.contains("API_KEY") })
    }

    func testAMissingOrEmptyRequiredValueIsFoundByName() {
        for key in ["API_KEY", "GOOGLE_APP_ID", "PROJECT_ID", "GCM_SENDER_ID"] {
            XCTAssertTrue(problems([key: nil]).contains { $0.contains(key) }, "\(key) missing")
            XCTAssertTrue(problems([key: ""]).contains { $0.contains(key) }, "\(key) empty")
        }
    }

    func testAnApplicationIdOfTheKnownVersionThatIsNotWellFormedIsFound() {
        for bad in ["1:123456789012:android:0123456789abcdef", "1:123456789012:ios:", "1:123456789012:ios:xyz", "1:abc:ios:0123", "1:123456789012:ios", "nonsense", "1:123456789012:ios:0123456789abcdef:extra"] {
            XCTAssertTrue(problems(["GOOGLE_APP_ID": bad]).contains { $0.contains("GOOGLE_APP_ID") }, bad)
        }
    }

    func testAFileThatIsNotAPropertyListOrNotADictionaryIsFound() {
        XCTAssertFalse(FirebaseConfigurationCheck.problems(in: Data("not a plist".utf8), bundleIdentifier: "to.kala.reach").isEmpty)
        let array = try! PropertyListSerialization.data(fromPropertyList: ["a", "b"], format: .xml, options: 0)
        XCTAssertFalse(FirebaseConfigurationCheck.problems(in: array, bundleIdentifier: "to.kala.reach").isEmpty)
        XCTAssertFalse(FirebaseConfigurationCheck.problems(in: Data(), bundleIdentifier: "to.kala.reach").isEmpty)
    }

    func testAValueThatIsNotTextIsFound() {
        XCTAssertTrue(problems(["API_KEY": 12345]).contains { $0.contains("API_KEY") })
    }

    // MARK: What would stop a message arriving

    func testAFileMadeForAnotherApplicationIsFound() {
        XCTAssertTrue(problems(["BUNDLE_ID": "com.example.other"]).contains { $0.contains("BUNDLE_ID") })
        XCTAssertTrue(problems(bundle: "to.kala.reach.other").contains { $0.contains("BUNDLE_ID") })
    }

    func testEveryProblemIsNamedAndNoneIsTheValueOfAKey() {
        let found = problems(["API_KEY": "SECRETSECRETSECRET", "PROJECT_ID": nil])
        XCTAssertGreaterThanOrEqual(found.count, 2)
        XCTAssertFalse(found.joined().contains("SECRETSECRETSECRET"), "a key is never put in what is said about it")
    }

    func testTheReasonTheLaunchGivesIsOneLineOfNames() {
        let reason = FirebaseConfigurationCheck.reason(for: ["API_KEY is not 39 characters", "PROJECT_ID is empty"])
        XCTAssertFalse(reason.contains("\n"))
        XCTAssertTrue(reason.contains("API_KEY"))
        XCTAssertTrue(reason.contains("PROJECT_ID"))
    }
}
