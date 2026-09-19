//
//  What the main application may sign, and when.
//
//  Section 16 puts one rule on the application half: it signs an action only after its required
//  authentication. The extension never signs anything at all, and it holds a key that cannot sign:
//  a preview key opens a preview and does nothing else.
//
//  The gate is a value rather than a flag on a singleton, so the rule is a thing a test can hold
//  and a caller cannot forget to ask.
//

import Foundation

/// Whether this process has the authentication signing requires.
enum AuthenticationState: Equatable {
    /// Nothing has been proved in this run.
    case none
    /// The person proved themselves, at a moment.
    case verified(atMilliseconds: UInt64)
}

/// Why a signature was refused.
enum SigningRefusal: Error, Equatable {
    /// Nothing has been proved in this run.
    case notAuthenticated
    /// The proof is older than this application accepts.
    case authenticationExpired
    /// The extension asked, and an extension never signs.
    case notTheApplication
}

/// How long an authentication stands before the application asks again.
let authenticationLifetimeMilliseconds: UInt64 = 5 * 60 * 1000

/// Decides whether an action may be signed now.
struct SigningGate {
    /// True in the application, false in every extension.
    let isMainApplication: Bool
    let state: AuthenticationState

    /// Admits an action for signing, or says why it is refused.
    func admit(nowMilliseconds: UInt64) throws {
        guard isMainApplication else { throw SigningRefusal.notTheApplication }
        switch state {
        case .none:
            throw SigningRefusal.notAuthenticated
        case let .verified(at):
            guard nowMilliseconds >= at else { throw SigningRefusal.authenticationExpired }
            guard nowMilliseconds - at <= authenticationLifetimeMilliseconds else {
                throw SigningRefusal.authenticationExpired
            }
        }
    }
}
