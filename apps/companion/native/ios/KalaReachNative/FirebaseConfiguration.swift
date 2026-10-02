//
//  Whether a build's Firebase configuration is one Firebase can start from.
//
//  Firebase raises an exception when its configuration has an API key it does not accept or an
//  application identifier it cannot read, and an exception raised at launch ends the application at
//  every launch. So the file is read here first, by the rules Firebase itself applies, and a file
//  that would stop it leaves the application running without push, with the reason named. The
//  reason names the keys and never holds their values: a key is the account's and is not said.
//

import Foundation

/// What the launch knows of the build's Firebase configuration.
enum FirebaseConfiguration: Equatable {
    /// Firebase can start from it.
    case usable
    /// It cannot, or there is none; the text says why, without a value from the file.
    case unusable(String)
}

enum FirebaseConfigurationCheck {
    /// The configuration of a build, from the file in its bundle if there is one.
    static func read(fileAt path: String?, bundleIdentifier: String) -> FirebaseConfiguration {
        guard let path else { return .unusable("this build holds no GoogleService-Info.plist") }
        guard let data = FileManager.default.contents(atPath: path) else {
            return .unusable("the build's GoogleService-Info.plist cannot be read")
        }
        let found = problems(in: data, bundleIdentifier: bundleIdentifier)
        return found.isEmpty ? .usable : .unusable(reason(for: found))
    }

    /// One line of what is wrong, for a log and for a check's result.
    static func reason(for problems: [String]) -> String {
        "GoogleService-Info.plist is not usable: " + problems.joined(separator: "; ")
    }

    /// What is wrong with a configuration, by the names of its keys; nothing when it is usable.
    static func problems(in data: Data, bundleIdentifier: String) -> [String] {
        guard
            let object = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
            let values = object as? [String: Any]
        else { return ["it is not a property list of keys and values"] }

        var found: [String] = []
        func text(_ key: String) -> String? {
            guard let value = values[key] else {
                found.append("\(key) is missing")
                return nil
            }
            guard let string = value as? String else {
                found.append("\(key) is not text")
                return nil
            }
            guard !string.isEmpty else {
                found.append("\(key) is empty")
                return nil
            }
            return string
        }

        if let key = text("API_KEY") { found += apiKeyProblems(key) }
        if let identifier = text("GOOGLE_APP_ID"), !isFormedAppIdentifier(identifier) {
            found.append("GOOGLE_APP_ID is not formed as Firebase reads it")
        }
        _ = text("PROJECT_ID")
        _ = text("GCM_SENDER_ID")
        if let made = text("BUNDLE_ID"), made != bundleIdentifier {
            found.append("BUNDLE_ID is not this application's identifier")
        }
        return found
    }

    /// The rules Firebase's installations library raises an exception for.
    private static func apiKeyProblems(_ key: String) -> [String] {
        var found: [String] = []
        if key.count != 39 { found.append("API_KEY is not 39 characters") }
        if !key.hasPrefix("A") { found.append("API_KEY does not start with A") }
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-_")
        if !allowed.isSuperset(of: CharacterSet(charactersIn: key)) {
            found.append("API_KEY has a character outside the URL-safe set")
        }
        return found
    }

    /// Firebase's own reading of the application identifier: a version, a project number, `ios` and a
    /// hash for the version it knows; any other version it leaves alone when it is well formed so far.
    private static func isFormedAppIdentifier(_ identifier: String) -> Bool {
        let scanner = Scanner(string: identifier)
        scanner.charactersToBeSkipped = nil
        guard let version = scanner.scanCharacters(from: .decimalDigits), scanner.scanString(":") != nil else {
            return false
        }
        guard version == "1" else { return true }
        guard scanner.scanInt() != nil, scanner.scanString(":") != nil else { return false }
        guard let platform = scanner.scanUpToString(":"), platform == "ios", scanner.scanString(":") != nil else {
            return false
        }
        guard scanner.scanUInt64(representation: .hexadecimal) != nil else { return false }
        return scanner.isAtEnd
    }
}
