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
    /// The run named after `-KRProbeRun`, which a script gives each check so that it reads the result
    /// of the check it started and never one an earlier check left behind.
    static func run(from arguments: [String]) -> String? {
        word(after: "-KRProbeRun", in: arguments)
    }

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

/// What a keychain answer means for a count and a sweep.
///
/// An empty group and a group that could not be read both find nothing, and only the first is a
/// clean baseline: a refusal counted as zero would let a sweep that deleted nothing say it left
/// nothing. So only an answer that found items, or said there are none, is a count.
enum KeychainAnswer {
    /// A count, or why there is none.
    enum Count: Equatable {
        case found(Int)
        case failed(OSStatus)
    }

    static func counted(status: OSStatus, found: Int) -> Count {
        switch status {
        case errSecSuccess: return .found(found)
        case errSecItemNotFound: return .found(0)
        default: return .failed(status)
        }
    }

    /// Whether a delete left nothing of what it was asked to remove.
    static func deleteLeftNothing(status: OSStatus) -> Bool {
        status == errSecSuccess || status == errSecItemNotFound
    }

    /// The two groups a check looks at, or nil when either is not named: a count of one group says
    /// nothing about the other.
    static func groupsToCount(shared: String?, private own: String?) -> [String]? {
        guard let shared, let own else { return nil }
        return [shared, own]
    }
}

/// Sorts the notifications an application was delivered by the send a check is reading.
///
/// A notification from an earlier send can arrive late and carry valid fields of its own, so one
/// counts only when it carries the nonce this send was made with.
enum DeliveredMarks {
    static func sort(
        _ userInfos: [[AnyHashable: Any]],
        nonce: String?
    ) -> (matching: [[AnyHashable: Any]], otherMarked: Int) {
        var matching: [[AnyHashable: Any]] = []
        var other = 0
        for info in userInfos {
            guard let marked = info["kr_probe_nonce"] as? String else { continue }
            if let nonce, marked == nonce {
                matching.append(info)
            } else {
                other += 1
            }
        }
        return (matching, other)
    }
}

/// How the push check ends, which it does once.
///
/// The check waits on Firebase with a timeout and on the person's answer, and can hear from either
/// after the other has ended it. Whichever comes first reports; what a second would have reported
/// or left behind is never reported or left. What a report leaves behind, other than the report, is
/// the file the next step reads to find the token it sends to, and it is left by the report that
/// counts, before that report is made, so a reader that waits for the report finds the file whole.
struct PushCheckReport {
    private(set) var reported = false
    let nonce: String
    let group: String
    let writeFile: (Data) -> Void
    let finish: ([String: String]) -> Void

    /// The person refused.
    mutating func refused(facts: [String: String]) {
        var facts = facts
        facts["permission"] = "refused"
        end(facts, leaving: nil)
    }

    /// Nothing came in time.
    mutating func timedOut(facts: [String: String], state: String, permission: String) {
        var facts = facts
        facts["token"] = "timeout"
        facts["state"] = state
        facts["permission"] = permission
        end(facts, leaving: nil)
    }

    /// Firebase answered with an error: only its domain and code are kept.
    mutating func failed(facts: [String: String], domain: String, code: Int) {
        var facts = facts
        facts["token"] = "error"
        facts["token.error"] = "\(domain)/\(code)"
        end(facts, leaving: nil)
    }

    /// Firebase answered with a token, which is filed for the next step.
    mutating func token(_ token: String, facts: [String: String]) {
        var facts = facts
        facts["token"] = "ready"
        let file = ["nonce": nonce, "group": group, "fcm_token": token]
        let write = writeFile
        end(facts, leaving: {
            if let data = try? JSONSerialization.data(withJSONObject: file) { write(data) }
        })
    }

    private mutating func end(_ facts: [String: String], leaving: (() -> Void)?) {
        guard !reported else { return }
        reported = true
        leaving?()
        finish(facts)
    }
}

/// What a run of the audio check saw, second by second.
///
/// Each tick says how long ago the check's own input and output last ran and whether the device's
/// protected data was available, which is how a locked phone shows itself to an application. The
/// gaps over every tick and over the ticks while the phone was locked are kept apart, because
/// audio that carries on through a lock is the thing being asked.
struct AudioTickLog {
    private let start: TimeInterval
    private(set) var ticks = 0
    private(set) var lockedTicks = 0
    private(set) var inputGap: TimeInterval = 0
    private(set) var outputGap: TimeInterval = 0
    private(set) var lockedInputGap: TimeInterval = 0
    private(set) var lockedOutputGap: TimeInterval = 0

    init(start: TimeInterval) { self.start = start }

    /// One reading. A time that has never been seen counts from the start of the check.
    mutating func tick(now: TimeInterval, lastInput: TimeInterval?, lastOutput: TimeInterval?, protectedDataAvailable: Bool) {
        let input = now - (lastInput ?? start)
        let output = now - (lastOutput ?? start)
        ticks += 1
        inputGap = max(inputGap, input)
        outputGap = max(outputGap, output)
        if !protectedDataAvailable {
            lockedTicks += 1
            lockedInputGap = max(lockedInputGap, input)
            lockedOutputGap = max(lockedOutputGap, output)
        }
    }

    /// The facts, with gaps in whole milliseconds.
    var facts: [String: String] {
        func ms(_ gap: TimeInterval) -> String { String(Int((gap * 1000).rounded())) }
        return [
            "ticks": String(ticks),
            "locked.ticks": String(lockedTicks),
            "gap.input.max": ms(inputGap),
            "gap.output.max": ms(outputGap),
            "gap.input.locked.max": ms(lockedInputGap),
            "gap.output.locked.max": ms(lockedOutputGap),
        ]
    }
}

/// The number of the next picture, after those a folder already holds: a check started again must
/// not write over the pictures of the one before it.
enum ShotNumbering {
    static func next(existing names: [String]) -> Int {
        let numbers = names.compactMap { name -> Int? in
            guard name.hasPrefix("shot-"), name.hasSuffix(".png") else { return nil }
            return Int(name.dropFirst("shot-".count).dropLast(".png".count))
        }
        return (numbers.max() ?? 0) + 1
    }
}
#endif
