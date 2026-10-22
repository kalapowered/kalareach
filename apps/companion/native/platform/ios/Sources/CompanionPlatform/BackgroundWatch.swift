import Tauri
import UIKit

/// Who is told when the application goes to the background.
///
/// This is the application's leaving the front, and nothing less: `applicationWillResignActive` is
/// sent for the Control Center, the Notification Center and the system's own questions as well, and
/// a person who turns on Wi-Fi in the middle of pairing has not left. What a phone read and has not
/// used is let go of on this one. The observer is added when the plugin is made, which is before the
/// application asks to be told, so no entry into the background is missed between the two.
final class BackgroundWatch {
  private let lock = NSLock()
  private var channels: [Channel] = []

  init() {
    NotificationCenter.default.addObserver(
      forName: UIApplication.didEnterBackgroundNotification, object: nil, queue: nil
    ) { [weak self] _ in self?.tell() }
  }

  /// Has `channel` told each time the application goes to the background.
  func watch(_ channel: Channel) {
    lock.lock()
    channels.append(channel)
    lock.unlock()
  }

  private func tell() {
    lock.lock()
    let listening = channels
    lock.unlock()
    let news: JsonObject = [:]
    for channel in listening { channel.send(news) }
  }
}
