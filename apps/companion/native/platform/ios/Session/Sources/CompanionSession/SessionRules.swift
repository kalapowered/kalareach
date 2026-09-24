import Foundation

/// How an authentication session takes its answer back.
public enum SessionCallback: Equatable {
  /// The HTTPS callback on the service's host and path, which the application's association with
  /// that domain lets the session claim.
  case https(host: String, path: String)
  /// The application's private-use scheme.
  case scheme(String)
}

/// What one attempt's authentication session is given.
public struct SessionConfiguration: Equatable {
  /// Where the answer comes back.
  public let callback: SessionCallback
  /// Always true: a sign-in shares no cookies with Safari, so every ceremony is one of its own.
  public let ephemeral: Bool
}

/// Whether the system's authentication session takes an HTTPS callback: from iOS 17.4.
public func takesHttpsCallback(_ version: OperatingSystemVersion) -> Bool {
  version.majorVersion > 17 || (version.majorVersion == 17 && version.minorVersion >= 4)
}

/// The session for one attempt, or none when the attempt cannot run here.
///
/// The attempt's mode was chosen from what this device reported, so an attempt that asks for the
/// HTTPS callback on a system without one is refused rather than given a session whose answer
/// could never come back.
public func sessionConfiguration(
  mode: String, httpsHost: String, httpsPath: String, scheme: String, httpsTaken: Bool
) -> SessionConfiguration? {
  switch mode {
  case "sessionHttps" where httpsTaken:
    return SessionConfiguration(callback: .https(host: httpsHost, path: httpsPath), ephemeral: true)
  case "sessionScheme":
    return SessionConfiguration(callback: .scheme(scheme), ephemeral: true)
  default:
    return nil
  }
}

/// The attempt the session under way belongs to, so each attempt is answered once and a late
/// completion of an earlier one is told apart.
public final class SessionAttempts {
  private var current: String?

  public init() {}

  /// The attempt under way, if any.
  public var inProgress: String? { current }

  /// Starts `attempt`, and answers the attempt it replaces, which is over.
  public func begin(_ attempt: String) -> String? {
    let earlier = current
    current = attempt
    return earlier
  }

  /// Ends `attempt` if it is the one under way, and answers whether it was.
  public func end(_ attempt: String) -> Bool {
    guard current == attempt else { return false }
    current = nil
    return true
  }
}
