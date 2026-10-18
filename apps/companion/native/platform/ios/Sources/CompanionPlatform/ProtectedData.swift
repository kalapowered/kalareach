import Tauri
import UIKit

/// What watching protected data takes: the channel its news is sent on.
struct WatchArguments: Decodable {
  let events: Channel
}

/// Whether the device's protected data can be read, and who is told when it becomes readable.
///
/// iOS keeps the application's files and keychain items out of its reach from a restart until the
/// person first unlocks the device, and posts `protectedDataDidBecomeAvailable` when that happens
/// and at each unlock after it. The observers are added when the plugin is made, which is before
/// the application asks to be told, so no unlock is missed between the two.
final class ProtectedData {
  private let lock = NSLock()
  private var readable = true
  private var channels: [Channel] = []

  init() {
    let center = NotificationCenter.default
    center.addObserver(
      forName: UIApplication.protectedDataDidBecomeAvailableNotification, object: nil, queue: nil
    ) { [weak self] _ in self?.changed(to: true) }
    center.addObserver(
      forName: UIApplication.protectedDataWillBecomeUnavailableNotification, object: nil, queue: nil
    ) { [weak self] _ in self?.changed(to: false) }
    // What it is now, read where the application's own properties are read.
    if Thread.isMainThread {
      readNow()
    } else {
      DispatchQueue.main.async { [weak self] in self?.readNow() }
    }
  }

  private func readNow() {
    set(UIApplication.shared.isProtectedDataAvailable)
  }

  /// Whether the data can be read as far as the system has said.
  var available: Bool {
    lock.lock()
    defer { lock.unlock() }
    return readable
  }

  /// Has `channel` told each time the data becomes readable.
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

  private func changed(to value: Bool) {
    lock.lock()
    readable = value
    let listening = value ? channels : []
    lock.unlock()
    let news: JsonObject = ["available": true]
    for channel in listening { channel.send(news) }
  }
}
