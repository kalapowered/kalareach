import Foundation

/// How the platform plugin reaches what the application holds about notifications.
///
/// What a phone knows about its notifications is the application's own, in a target the plugin's
/// package cannot see: whether the person allowed them, the token the provider gave this
/// installation, the record of the registration being waited for, the limited key store the
/// notification extension reads, and the screen a tap opened. So the plugin finds the application's
/// adapter by the name of its class and sends it a request by selector, as it does the voice call.
public enum PushLink {
  /// The adapter's class, as the runtime knows it.
  public static let adapterClass = "KRPushAdapter"

  /// The class method that returns the one adapter.
  public static let sharedSelector = "krShared"

  /// The instance method that takes one request.
  public static let callSelector = "krCall:"

  /// The keys of the dictionary one request is.
  public enum Key {
    /// The command's name.
    public static let command = "command"
    /// The command's arguments, as JSON text.
    public static let arguments = "arguments"
    /// A block that takes the command's one answer: its result as JSON text, or a code and a
    /// message.
    public static let reply = "reply"
  }

  /// The commands the adapter takes.
  public static let commands = [
    "pushPermission", "pushAskPermission", "pushToken", "pushTokenChanged", "pushPendingSet",
    "pushPendingGet", "pushPendingClear", "pushLimitedKey", "pushRoute",
  ]

  /// What a command's answer is: the result as JSON text, or a code and a message.
  public typealias Reply = @convention(block) (NSString?, NSString?, NSString?) -> Void

  /// The adapter, or nothing when the application has not got one.
  public static func adapter() -> NSObject? {
    guard let adapterType = NSClassFromString(adapterClass) as? NSObject.Type,
      adapterType.responds(to: NSSelectorFromString(sharedSelector))
    else { return nil }
    return adapterType.perform(NSSelectorFromString(sharedSelector))?.takeUnretainedValue()
      as? NSObject
  }

  /// One request to the adapter. False when the adapter cannot take it.
  @discardableResult
  public static func send(_ command: String, arguments: String, reply: @escaping Reply) -> Bool {
    guard let adapter = adapter(), adapter.responds(to: NSSelectorFromString(callSelector)) else {
      return false
    }
    let request: [String: Any] = [
      Key.command: command as NSString,
      Key.arguments: arguments as NSString,
      Key.reply: reply as AnyObject,
    ]
    _ = adapter.perform(NSSelectorFromString(callSelector), with: request as NSDictionary)
    return true
  }
}
