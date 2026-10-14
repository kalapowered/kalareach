import Foundation

/// How the platform plugin reaches the voice call the application holds.
///
/// The call is the application's own, in a target the plugin's package cannot see, so the plugin
/// finds its adapter by the name of its class and sends it a request by selector. The names, the
/// keys of the request and the commands are the fixture `link.json`, which the application's tests
/// check its adapter against and this package's tests check these against: neither side can
/// rename one without the other's tests failing.
public enum CallLink {
  /// The adapter's class, as the runtime knows it.
  public static let adapterClass = "KRCallAdapter"

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
    /// A block that takes one item of the call's news, as JSON text. Only the command that opens
    /// a call carries it.
    public static let news = "news"
    /// A block that takes the command's one answer: its result as JSON text, or a code and a
    /// message.
    public static let reply = "reply"
  }

  /// The commands the adapter takes.
  public static let commands = [
    "callOpen", "callOffer", "callAccept", "callPermit", "callMute", "callStop", "callState",
  ]

  /// What a command's answer is: the result as JSON text, or a code from the closed set and a
  /// message.
  public typealias Reply = @convention(block) (NSString?, NSString?, NSString?) -> Void

  /// What one item of the call's news is: JSON text.
  public typealias News = @convention(block) (NSString) -> Void

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
  public static func send(
    _ command: String, arguments: String, news: News? = nil, reply: @escaping Reply
  ) -> Bool {
    guard let adapter = adapter(), adapter.responds(to: NSSelectorFromString(callSelector)) else {
      return false
    }
    var request: [String: Any] = [
      Key.command: command as NSString,
      Key.arguments: arguments as NSString,
      Key.reply: reply as AnyObject,
    ]
    if let news = news { request[Key.news] = news as AnyObject }
    _ = adapter.perform(NSSelectorFromString(callSelector), with: request as NSDictionary)
    return true
  }
}
