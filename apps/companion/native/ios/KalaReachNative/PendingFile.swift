//
//  The record of the one registration this phone is waiting for the challenge of.
//
//  The application writes it before it proposes a token, and the receiver reads it when a challenge
//  arrives, in a process the system woke for that push alone. It holds nothing secret: the
//  identifiers a challenge has to repeat, the gateway to answer to and the phone's own deadline.
//  The Rust half owns what the fields mean; this keeps the text and moves one field, `state`, as
//  the registration moves.
//
//  A write replaces the file whole, so a reader sees the old record or the new one. A record whose
//  deadline has passed reads as `expired` on every read, whether or not the process that wrote it
//  still runs: expiry is a fact of the clock, not of a timer, because nothing guarantees a timer in
//  a suspended process.
//

import Foundation

final class PendingFile {
    /// A registration waiting for its challenge.
    static let pending = "pending"
    /// A registration whose challenge was answered and taken by the gateway.
    static let answered = "answered"
    /// A registration the receiver or the gateway refused.
    static let refused = "refused"
    /// A registration whose deadline passed.
    static let expired = "expired"

    /// The file's name, in the application's own data directory.
    static let fileName = "push-pending.json"

    private let url: URL
    private let lock = NSLock()

    init(url: URL) { self.url = url }

    /// The record in the application's data directory.
    static func inApplicationSupport() -> PendingFile? {
        guard let directory = try? FileManager.default.url(
            for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true
        ) else { return nil }
        return PendingFile(url: directory.appendingPathComponent(fileName))
    }

    /// The record as text, in the state it is in now, or nil when there is none.
    func read(nowMilliseconds: UInt64) -> String? {
        lock.lock()
        defer { lock.unlock() }
        guard var record = load() else { return nil }
        if (record["state"] as? String) == Self.pending,
            nowMilliseconds >= deadline(of: record)
        {
            record["state"] = Self.expired
            try? store(record)
        }
        return text(of: record)
    }

    /// Replaces the record, which supersedes whatever was there.
    func write(_ text: String) throws {
        lock.lock()
        defer { lock.unlock() }
        guard
            let data = text.data(using: .utf8),
            let record = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { throw CocoaError(.coderReadCorrupt) }
        try store(record)
    }

    /// Removes the record.
    func clear() throws {
        lock.lock()
        defer { lock.unlock() }
        if FileManager.default.fileExists(atPath: url.path) {
            try FileManager.default.removeItem(at: url)
        }
    }

    /// Moves a record that is still `pending` to `state`, with the reason when there is one. False
    /// when there is no such record: one that was replaced or has expired is left alone.
    @discardableResult
    func mark(state: String, reason: String?, nowMilliseconds: UInt64) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard var record = load(), (record["state"] as? String) == Self.pending else { return false }
        if nowMilliseconds >= deadline(of: record) {
            record["state"] = Self.expired
            try? store(record)
            return false
        }
        record["state"] = state
        if let reason { record["reason"] = reason }
        do { try store(record) } catch { return false }
        return true
    }

    private func deadline(of record: [String: Any]) -> UInt64 {
        (record["deadline_ms"] as? NSNumber)?.uint64Value ?? 0
    }

    private func load() -> [String: Any]? {
        guard let data = try? Data(contentsOf: url) else { return nil }
        return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
    }

    private func text(of record: [String: Any]) -> String? {
        guard let data = try? JSONSerialization.data(withJSONObject: record, options: [.sortedKeys]) else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }

    private func store(_ record: [String: Any]) throws {
        let data = try JSONSerialization.data(withJSONObject: record, options: [.sortedKeys])
        // Readable after the first unlock, which is when a push can wake the application usefully.
        try data.write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
    }
}
