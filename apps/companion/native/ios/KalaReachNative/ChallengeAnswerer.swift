//
//  Answering a registration challenge, from the receiver the system wakes for a push.
//
//  The decision and the signature are the Rust half's, behind two functions (`ChallengeCrypto`): one
//  decides, from the message and the pending record, whether this is the challenge of the
//  registration the phone is waiting for, and needs no secret; the other builds the answer and the
//  signed request that carries it, and reads the installation's key from the application's own
//  keychain group, only after the first said to go on. This keeps the order, posts what it is given
//  to the gateway the record names, and moves the record to what became of it.
//
//  What it never does: answer a message the decision refused, or post anywhere but the address the
//  decision returned.
//

import Foundation

/// The Rust half's two functions, over JSON text.
protocol ChallengeCrypto {
    /// Decides what a message means for the pending registration, with no secret.
    func classify(_ input: String) -> String
    /// Builds the answer and the request that carries it, reading the key itself.
    func sign(_ input: String) -> String
}

/// What came back from the gateway, or that nothing did.
enum PostResult: Equatable {
    case status(Int)
    case unreachable
}

/// The one request this answers with.
protocol GatewayPost {
    func post(url: String, body: Data, then: @escaping (PostResult) -> Void)
}

/// What became of one message.
enum ChallengeOutcome: Equatable {
    /// The message is not a registration challenge.
    case notAChallenge
    /// It is one, and is not answered, for the reason named. The record is as it was.
    case ignored(String)
    /// The gateway took the answer.
    case answered
    /// The gateway answered and will not take it. The record says so.
    case gatewayRefused(Int)
    /// The answer did not get there, or the gateway could not take it now.
    case retry(String)
}

final class ChallengeAnswerer {
    private let record: PendingFile
    private let crypto: ChallengeCrypto
    private let gateway: GatewayPost
    private let clock: () -> UInt64

    init(
        record: PendingFile,
        crypto: ChallengeCrypto,
        gateway: GatewayPost,
        clock: @escaping () -> UInt64 = { UInt64(Date().timeIntervalSince1970 * 1000) }
    ) {
        self.record = record
        self.crypto = crypto
        self.gateway = gateway
        self.clock = clock
    }

    /// Answers one message's data, and says what became of it once the gateway has answered.
    func answer(_ data: [String: String], then done: @escaping (ChallengeOutcome) -> Void) {
        let now = clock()
        var input: [String: Any] = ["data": data, "now_ms": now]
        let pending = record.read(nowMilliseconds: now)
            .flatMap { $0.data(using: .utf8) }
            .flatMap { try? JSONSerialization.jsonObject(with: $0) }
        input["pending"] = pending ?? NSNull()
        // The registration this answer is for: the one the decision is made against, so that what
        // becomes of the answer is written to that registration's record and to no later one.
        let registrationId = ((pending as? [String: Any])?["registration_id"] as? String) ?? ""
        guard
            let body = try? JSONSerialization.data(withJSONObject: input),
            let text = String(data: body, encoding: .utf8),
            let verdict = Self.object(crypto.classify(text))
        else { return done(.ignored("input")) }

        switch verdict["verdict"] as? String {
        case "not_a_challenge": return done(.notAChallenge)
        case "answer": break
        // A refusal leaves the record as it was: a message that is not this registration's
        // challenge says nothing about this registration, and must not end it.
        default: return done(.ignored((verdict["reason"] as? String) ?? "refused"))
        }

        guard let signed = Self.object(crypto.sign(text)) else { return done(.ignored("signing")) }
        guard (signed["ok"] as? Bool) == true,
            let url = signed["url"] as? String,
            let request = (signed["body"] as? String)?.data(using: .utf8)
        else { return done(.ignored((signed["reason"] as? String) ?? "not_signed")) }

        gateway.post(url: url, body: request) { [self] result in
            switch result {
            case .unreachable:
                done(.retry("unreachable"))
            case .status(let code) where (200...299).contains(code):
                record.mark(registrationId: registrationId, state: PendingFile.answered, reason: nil, nowMilliseconds: clock())
                done(.answered)
            // The gateway answered and will not take it, or is not able to now. The second is
            // asked again inside the deadline; the first would be refused again.
            case .status(let code) where code == 408 || code == 429 || code >= 500:
                done(.retry("status_\(code)"))
            case .status(let code):
                record.mark(registrationId: registrationId, state: PendingFile.refused, reason: "gateway_\(code)", nowMilliseconds: clock())
                done(.gatewayRefused(code))
            }
        }
    }

    private static func object(_ text: String) -> [String: Any]? {
        guard let data = text.data(using: .utf8) else { return nil }
        return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
    }
}
