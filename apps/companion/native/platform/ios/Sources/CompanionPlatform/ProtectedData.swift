import Tauri
import UIKit

/// What watching protected data takes: the channel its news is sent on.
struct WatchArguments: Decodable {
  let events: Channel
}

/// Whether the device's protected data can be read, and who is told when it may have become readable.
///
/// iOS keeps the application's files and keychain items out of its reach from a restart until the
/// person first unlocks the device, and posts `protectedDataDidBecomeAvailable` to a running
/// process when that happens and at each unlock after it. A process that was started in the
/// background and suspended before the unlock is not running when the system posts it, so the
/// application coming to the foreground is told as well: a person who opens it has unlocked the
/// device. The observers are added when the plugin is made, which is before the application asks to
/// be told, so no unlock is missed between the two. What the system says is first read when the
/// window is made (`refresh`): the plugin is made before the application object exists.
final class ProtectedData {
  private let lock = NSLock()
  private var readable = true
  private var channels: [Channel] = []

  init() {
    let center = NotificationCenter.default
    center.addObserver(
      forName: UIApplication.protectedDataDidBecomeAvailableNotification, object: nil, queue: nil
    ) { [weak self] _ in
      self?.set(true)
      self?.tell()
    }
    center.addObserver(
      forName: UIApplication.protectedDataWillBecomeUnavailableNotification, object: nil, queue: nil
    ) { [weak self] _ in self?.set(false) }
    center.addObserver(
      forName: UIApplication.willEnterForegroundNotification, object: nil, queue: nil
    ) { [weak self] _ in
      self?.refresh()
      self?.tell()
    }
  }

  /// Reads what the system says now. It is called on the main thread, where the application's own
  /// properties are read, and only once the application object exists.
  func refresh() {
    set(UIApplication.shared.isProtectedDataAvailable)
  }

  /// Whether the data can be read as far as the system has said.
  var available: Bool {
    lock.lock()
    defer { lock.unlock() }
    return readable
  }

  /// Has `channel` told each time the data may have become readable.
  func watch(_ channel: Channel) {
    lock.lock()
    channels.append(channel)
    lock.unlock()
  }

  private func set(_ value: Bool) {
    lock.lock()
    readable = value
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
