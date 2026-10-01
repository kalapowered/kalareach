//
//  The device checks' own support: what a check asked for, the keychain queries it cleans up
//  with, and how it reports. Compiled into debug builds only.
//

#if DEBUG
import Foundation
import Security

/// A check a debug build can be started to run, named after `-KRDeviceProbe`.
enum ProbeMode: String {
    /// Counts the items in the application's two keychain groups, by attributes alone.
    case count
    /// Writes the check's fixtures and reads them back.
    case keychain
    /// Asks for the notification permission, then reports the two tokens.
    case push
    /// Reads the notifications this application has been delivered.
    case pushRead = "push-read"
    /// Opens the audio session and measures it.
    case audio
    /// Removes everything in the two groups and checks that nothing is left.
    case sweep
    /// Renders the application's own window to a file when asked to.
    case shots
}

/// A colour mode a debug build can be started in, named after `-KRColourMode`.
enum ProbeColourMode: String {
    case light
    case dark
}

/// Reads the flags a check was started with.
enum ProbeArguments {
    /// The mode named after `-KRDeviceProbe`, or nil when there is none or it is not one.
    static func mode(from arguments: [String]) -> ProbeMode? {
        word(after: "-KRDeviceProbe", in: arguments).flatMap(ProbeMode.init(rawValue:))
    }

    /// The mode named after `-KRColourMode`, or nil.
    static func colourMode(from arguments: [String]) -> ProbeColourMode? {
        word(after: "-KRColourMode", in: arguments).flatMap(ProbeColourMode.init(rawValue:))
    }

    private static func word(after flag: String, in arguments: [String]) -> String? {
        guard let at = arguments.firstIndex(of: flag), arguments.indices.contains(at + 1) else { return nil }
        return arguments[at + 1]
    }
}

/// One keychain query, with the group it is about.
struct KeychainQuery {
    let group: String
    let query: [String: Any]
}

/// The queries a count and a sweep make over the application's groups.
///
/// Every item class is covered, because a library that writes to the keychain is free to choose
/// one. Synchronisable items are covered too, which a query without the attribute leaves out. A
/// count reads attributes and never a value: what a check needs to know is whether anything is
/// there, and it has no business reading what.
struct KeychainSweepPlan {
    let groups: [String]

    private static let classes: [CFString] = [
        kSecClassGenericPassword,
        kSecClassInternetPassword,
        kSecClassCertificate,
        kSecClassKey,
        kSecClassIdentity,
    ]

    func countQueries() -> [KeychainQuery] {
        queries { base in
            var query = base
            query[kSecReturnAttributes as String] = true
            query[kSecMatchLimit as String] = kSecMatchLimitAll
            return query
        }
    }

    func deleteQueries() -> [KeychainQuery] {
        queries { $0 }
    }

    private func queries(_ shape: ([String: Any]) -> [String: Any]) -> [KeychainQuery] {
        groups.flatMap { group in
            Self.classes.map { itemClass in
                KeychainQuery(
                    group: group,
                    query: shape([
                        kSecClass as String: itemClass,
                        kSecAttrAccessGroup as String: group,
                        kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
                    ])
                )
            }
        }
    }
}

/// What a check reports, as lines the test reads back.
struct ProbeReport {
    private var facts: [String: String] = [:]

    mutating func set(_ key: String, _ value: String) {
        facts[key] = value
    }

    var text: String {
        facts.keys.sorted().map { "\($0)=\(facts[$0] ?? "")" }.joined(separator: "\n")
    }
}
#endif
