import AVFoundation
import CompanionScan
import PhotosUI
import UIKit
import UniformTypeIdentifiers

/// What reading a code came to: the text of the code, that the person closed the scanner or the
/// picker, that a picture showed no code, that the camera is not allowed, or that the camera could
/// not be started or the picture opened.
///
/// The text of a code holds an invitation's secret, so printing an outcome never shows it.
enum ScanOutcome: CustomStringConvertible, CustomDebugStringConvertible {
  case text(String)
  case cancelled
  case noCode
  case cameraDenied
  case failed

  var description: String {
    switch self {
    case .text: return "text(..)"
    case .cancelled: return "cancelled"
    case .noCode: return "noCode"
    case .cameraDenied: return "cameraDenied"
    case .failed: return "failed"
    }
  }

  var debugDescription: String { description }
}

/// The one answer a request to read a code gets, in the words the plugin's Rust half reads. Printing
/// one never shows the text it carries.
struct ScanAnswer: Encodable, CustomStringConvertible, CustomDebugStringConvertible {
  let outcome: String
  var text: String? = nil

  var description: String { text == nil ? "ScanAnswer(\(outcome))" : "ScanAnswer(\(outcome), ..)" }
  var debugDescription: String { description }

  init(_ outcome: ScanOutcome) {
    switch outcome {
    case .text(let found):
      self.outcome = "text"
      self.text = found
    case .cancelled: self.outcome = "cancelled"
    case .noCode: self.outcome = "no_code"
    case .cameraDenied: self.outcome = "camera_denied"
    case .failed: self.outcome = "failed"
    }
  }
}

/// What a reader hands over when it answers, after the scanner or the picker has left the screen.
///
/// A code is handed over only by an application that is in front now and has been in front since
/// the reading began. The scanner and the picker watch for the application going to the background,
/// but their dismissal takes a moment, and the code was decoded before it: an application that left
/// in between gives the code to nobody, and the answer is that the scan was cancelled.
private func handedOver(_ outcome: ScanOutcome, leftTheFront: Bool) -> ScanOutcome {
  if case .text = outcome, leftTheFront || UIApplication.shared.applicationState == .background {
    return .cancelled
  }
  return outcome
}

/// A scan that has been asked for, which can be ended before the scanner is on the screen.
final class ScanHandle {
  fileprivate(set) var scanner: CodeScannerViewController?
  fileprivate(set) var ended = false

  /// Ends the scan with a cancel: the scanner closes when it is shown, and is never shown when it
  /// is not yet.
  func cancel() {
    ended = true
    scanner?.finish(.cancelled)
  }
}

/// The full-screen scanner: the camera behind a rounded square, a hint above it, Cancel at the top
/// left and a torch control when the device has a torch.
///
/// A frame is read for a QR code at most a few times a second, which is as fast as a person can
/// hold a code up, and the first text read ends the scan. The scanner has no moving decoration: it
/// says nothing the preview does not. When it reads a code the outline takes the accent colour and
/// the scanner closes a moment later, and VoiceOver says the code was found. What the camera sees
/// is kept out of the application switcher's picture: the preview is hidden when the application
/// stops being active, and the scan ends when it goes to the background.
final class CodeScannerViewController: UIViewController, AVCaptureVideoDataOutputSampleBufferDelegate {
  private let session = AVCaptureSession()
  private let frames = DispatchQueue(label: "to.kala.reach.scanner.frames")
  private let preview = AVCaptureVideoPreviewLayer()
  private let outline = CAShapeLayer()
  private let hint = UILabel()
  private let cancel = UIButton(type: .system)
  private let torch = UIButton(type: .system)
  private var device: AVCaptureDevice?
  private var done: ((ScanOutcome) -> Void)?
  private var finished = false
  /// How the scan ended while the scanner was still coming onto the screen: UIKit ignores a
  /// dismissal asked for then, so the scan ends when the scanner has appeared.
  private var deferred: ScanOutcome?
  private var appeared = false
  /// Whether the camera was set up: when it was not, the scanner has nothing to show.
  private var setUp = false
  private var found = false
  /// The application went to the background while the scan was under way, or while it closed.
  private var leftTheFront = false
  /// Watches for that until the answer is given, which is after the scanner has gone from the
  /// screen: the scan's other observers go as soon as it ends.
  private var backgroundWatch: NSObjectProtocol?
  private var lastRead = CFAbsoluteTime(0)
  private static let readEvery: CFAbsoluteTime = 0.12

  /// Shows the scanner on `presenter`, after the camera is allowed, and answers `done` once. The
  /// handle ends the scan early.
  static func scan(from presenter: UIViewController, done: @escaping (ScanOutcome) -> Void) -> ScanHandle {
    let handle = ScanHandle()
    guard AVCaptureDevice.default(for: .video) != nil else {
      done(.cameraDenied)
      return handle
    }
    let present = {
      guard !handle.ended else {
        done(.cancelled)
        return
      }
      let scanner = CodeScannerViewController()
      scanner.done = done
      scanner.modalPresentationStyle = .fullScreen
      scanner.view.accessibilityViewIsModal = true
      handle.scanner = scanner
      presenter.present(scanner, animated: !UIAccessibility.isReduceMotionEnabled)
    }
    switch AVCaptureDevice.authorizationStatus(for: .video) {
    case .authorized:
      present()
    case .notDetermined:
      AVCaptureDevice.requestAccess(for: .video) { granted in
        DispatchQueue.main.async { granted ? present() : done(.cameraDenied) }
      }
    default:
      done(.cameraDenied)
    }
    return handle
  }

  override func viewDidLoad() {
    super.viewDidLoad()
    view.backgroundColor = .black
    setUp = configureCamera()
    preview.session = session
    preview.videoGravity = .resizeAspectFill
    view.layer.addSublayer(preview)

    outline.fillColor = UIColor.clear.cgColor
    outline.strokeColor = UIColor.white.cgColor
    outline.lineWidth = 4
    view.layer.addSublayer(outline)

    hint.text = "Point the camera at the code on your host"
    hint.textColor = .white
    hint.textAlignment = .center
    hint.numberOfLines = 0
    hint.font = UIFont.preferredFont(forTextStyle: .body)
    hint.adjustsFontForContentSizeCategory = true
    view.addSubview(hint)

    cancel.setTitle("Cancel", for: .normal)
    cancel.setTitleColor(.white, for: .normal)
    cancel.titleLabel?.font = UIFont.preferredFont(forTextStyle: .body)
    cancel.titleLabel?.adjustsFontForContentSizeCategory = true
    cancel.accessibilityLabel = "Cancel"
    cancel.addTarget(self, action: #selector(cancelTapped), for: .touchUpInside)
    view.addSubview(cancel)

    if device?.hasTorch == true {
      torch.setImage(UIImage(systemName: "flashlight.off.fill"), for: .normal)
      torch.tintColor = .white
      torch.accessibilityLabel = "Torch"
      torch.accessibilityValue = "Off"
      torch.addTarget(self, action: #selector(torchTapped), for: .touchUpInside)
      view.addSubview(torch)
    }

    let center = NotificationCenter.default
    center.addObserver(
      self, selector: #selector(hidePreview), name: UIApplication.willResignActiveNotification, object: nil)
    center.addObserver(
      self, selector: #selector(showPreview), name: UIApplication.didBecomeActiveNotification, object: nil)
    backgroundWatch = center.addObserver(
      forName: UIApplication.didEnterBackgroundNotification, object: nil, queue: .main
    ) { [weak self] _ in
      self?.leftTheFront = true
      self?.finish(.cancelled)
    }
    // A camera another application takes, or one that fails while it runs, leaves a black screen
    // with nothing to say: the scan ends and says the camera could not be used.
    center.addObserver(
      self, selector: #selector(cameraFailed), name: .AVCaptureSessionRuntimeError, object: session)
    center.addObserver(
      self, selector: #selector(cameraInterrupted(_:)), name: .AVCaptureSessionWasInterrupted, object: session)
  }

  override func viewDidAppear(_ animated: Bool) {
    super.viewDidAppear(animated)
    appeared = true
    if let outcome = deferred {
      deferred = nil
      finish(outcome)
      return
    }
    guard !finished else { return }
    guard setUp else {
      finish(.failed)
      return
    }
    frames.async { self.session.startRunning() }
    UIAccessibility.post(notification: .screenChanged, argument: hint)
  }

  /// VoiceOver's escape gesture closes the scanner as Cancel does.
  override func accessibilityPerformEscape() -> Bool {
    cancelTapped()
    return true
  }

  override func viewDidLayoutSubviews() {
    super.viewDidLayoutSubviews()
    preview.frame = view.bounds
    let side = min(view.bounds.width, view.bounds.height) * 0.7
    let square = CGRect(
      x: (view.bounds.width - side) / 2, y: (view.bounds.height - side) / 2, width: side, height: side)
    outline.path = UIBezierPath(roundedRect: square, cornerRadius: 24).cgPath
    let margin = view.safeAreaInsets
    // The controls follow the text size: the label is as wide and tall as its words need at the
    // size the person chose, and never smaller than a finger.
    let room = CGSize(width: view.bounds.width / 2, height: .greatestFiniteMagnitude)
    let words = cancel.sizeThatFits(room)
    cancel.frame = CGRect(
      x: 16, y: margin.top + 8, width: max(88, words.width + 24), height: max(44, words.height + 16))
    torch.frame = CGRect(x: view.bounds.width - 16 - 44, y: margin.top + 8, width: 44, height: 44)
    // The hint sits above the square and below the controls, and keeps clear of them when the text
    // is large: it runs over the preview rather than under Cancel.
    let wide = view.bounds.width - 48
    let height = hint.sizeThatFits(CGSize(width: wide, height: .greatestFiniteMagnitude)).height
    let lowest = max(cancel.frame.maxY, torch.frame.maxY) + 8
    hint.frame = CGRect(x: 24, y: max(lowest, square.minY - 24 - height), width: wide, height: height)
  }

  /// Sets the camera up, and says whether it could be: a camera with no input, or a session that
  /// takes no input or no output, is one the scanner cannot read from.
  private func configureCamera() -> Bool {
    guard
      let camera = AVCaptureDevice.default(.builtInWideAngleCamera, for: .video, position: .back)
        ?? AVCaptureDevice.default(for: .video),
      let input = try? AVCaptureDeviceInput(device: camera)
    else { return false }
    device = camera
    session.beginConfiguration()
    // A host's direct invitation is a version-23 code, 109 modules wide: it needs more than the
    // default preview resolution to be read from a hand's length.
    session.sessionPreset = session.canSetSessionPreset(.hd1920x1080) ? .hd1920x1080 : .high
    let output = AVCaptureVideoDataOutput()
    output.alwaysDiscardsLateVideoFrames = true
    output.setSampleBufferDelegate(self, queue: frames)
    let usable = session.canAddInput(input) && session.canAddOutput(output)
    if usable {
      session.addInput(input)
      session.addOutput(output)
    }
    session.commitConfiguration()
    return usable
  }

  // MARK: Frames

  func captureOutput(
    _ output: AVCaptureOutput, didOutput sampleBuffer: CMSampleBuffer, from connection: AVCaptureConnection
  ) {
    let now = CFAbsoluteTimeGetCurrent()
    guard now - lastRead >= Self.readEvery, let frame = CMSampleBufferGetImageBuffer(sampleBuffer) else { return }
    lastRead = now
    // The back camera's frames are turned a quarter relative to a phone held upright.
    guard let text = QrReader.text(in: frame, orientation: .right) else { return }
    DispatchQueue.main.async { self.read(text) }
  }

  /// A code was read: say so, and close once the outline has shown it.
  private func read(_ text: String) {
    guard !found, !finished else { return }
    found = true
    outline.strokeColor = view.tintColor.cgColor
    UIAccessibility.post(notification: .announcement, argument: "Code found")
    DispatchQueue.main.asyncAfter(deadline: .now() + 0.15) { self.finish(.text(text)) }
  }

  // MARK: Controls

  @objc private func cancelTapped() { finish(.cancelled) }

  @objc private func cameraFailed() { finish(.failed) }

  /// The application leaving the front takes the camera from it as well. That ends the scan as a
  /// cancel, by the observer of the application's going to the background, and is no fault of the
  /// camera; any other interruption leaves the scanner with nothing to show.
  @objc private func cameraInterrupted(_ note: Notification) {
    if let raw = note.userInfo?[AVCaptureSessionInterruptionReasonKey] as? Int,
      AVCaptureSession.InterruptionReason(rawValue: raw) == .videoDeviceNotAvailableInBackground
    {
      return
    }
    finish(.failed)
  }

  @objc private func torchTapped() {
    guard let device = device, device.hasTorch else { return }
    do {
      try device.lockForConfiguration()
      let on = device.torchMode == .off
      device.torchMode = on ? .on : .off
      device.unlockForConfiguration()
      torch.setImage(UIImage(systemName: on ? "flashlight.on.fill" : "flashlight.off.fill"), for: .normal)
      torch.accessibilityValue = on ? "On" : "Off"
    } catch {}
  }

  /// What the camera sees is not shown in the application switcher, so it goes at once: the layer's
  /// own change would fade it, and the picture the switcher takes would be of the fade.
  @objc private func hidePreview() { setPreview(hidden: true) }
  @objc private func showPreview() { setPreview(hidden: false) }

  private func setPreview(hidden: Bool) {
    CATransaction.begin()
    CATransaction.setDisableActions(true)
    preview.isHidden = hidden
    CATransaction.commit()
  }

  /// Ends the scan once, whichever of the person, a code or the system ends it first, and answers
  /// after the scanner has gone from the screen.
  func finish(_ outcome: ScanOutcome) {
    guard !finished else { return }
    if !appeared {
      if deferred == nil { deferred = outcome }
      return
    }
    finished = true
    NotificationCenter.default.removeObserver(self)
    frames.async {
      if self.device?.torchMode == .on, (try? self.device?.lockForConfiguration()) != nil {
        self.device?.torchMode = .off
        self.device?.unlockForConfiguration()
      }
      self.session.stopRunning()
    }
    let answer = done
    done = nil
    dismiss(animated: !UIAccessibility.isReduceMotionEnabled) { [self] in
      let handed = handedOver(outcome, leftTheFront: leftTheFront)
      if let watching = backgroundWatch { NotificationCenter.default.removeObserver(watching) }
      backgroundWatch = nil
      answer?(handed)
    }
  }
}

/// The system's picker for one picture. It hands this application only the picture the person
/// chose, and needs no permission to the photo library.
///
/// It answers once. A pick the person has not finished, or a picture still being read, ends with a
/// cancel when a newer request or the application's going to the background comes first, and what
/// the picture shows after that is dropped: nothing is held for a person who has gone. The
/// application is watched until the answer is given, after the picker has gone from the screen.
final class PhotoReader: NSObject, PHPickerViewControllerDelegate {
  private var done: ((ScanOutcome) -> Void)?
  private weak var picker: PHPickerViewController?
  private var background: NSObjectProtocol?
  private var leftTheFront = false
  /// Whether the picker has finished coming onto the screen: UIKit ignores a dismissal asked for
  /// before, so a cancel that comes sooner waits for it.
  private var presented = false
  private var cancelWhenPresented = false

  /// Ends the pick with a cancel, closing the picker. It does nothing once the pick is answered.
  func cancel() {
    guard done != nil else { return }
    guard presented else {
      cancelWhenPresented = true
      return
    }
    finish(.cancelled)
  }

  /// Shows the picker on `presenter` and answers `done` once, with the code in the chosen picture.
  func pick(from presenter: UIViewController, done: @escaping (ScanOutcome) -> Void) {
    var configuration = PHPickerConfiguration()
    configuration.filter = .images
    configuration.selectionLimit = 1
    let picker = PHPickerViewController(configuration: configuration)
    picker.delegate = self
    self.done = done
    self.picker = picker
    background = NotificationCenter.default.addObserver(
      forName: UIApplication.didEnterBackgroundNotification, object: nil, queue: .main
    ) { [weak self] _ in
      self?.leftTheFront = true
      self?.cancel()
    }
    presenter.present(picker, animated: true) { [weak self] in
      guard let self = self else { return }
      self.presented = true
      if self.cancelWhenPresented { self.finish(.cancelled) }
    }
  }

  func picker(_ picker: PHPickerViewController, didFinishPicking results: [PHPickerResult]) {
    guard let provider = results.first?.itemProvider else {
      finish(.cancelled)
      return
    }
    // The picture is read in memory, and never written anywhere.
    provider.loadDataRepresentation(forTypeIdentifier: UTType.image.identifier) { data, _ in
      // A picture that could not be opened is not a picture with no code.
      let outcome: ScanOutcome
      if let data = data {
        outcome = QrReader.text(in: data).map { .text($0) } ?? .noCode
      } else {
        outcome = .failed
      }
      DispatchQueue.main.async { self.finish(outcome) }
    }
  }

  /// Answers once, after the picker has gone from the screen: with `outcome`, unless a cancel
  /// answered first.
  private func finish(_ outcome: ScanOutcome) {
    guard let answer = done else { return }
    done = nil
    close(picker) { [self] in
      let handed = handedOver(outcome, leftTheFront: leftTheFront)
      stopWatching()
      answer(handed)
    }
  }

  private func stopWatching() {
    if let observer = background { NotificationCenter.default.removeObserver(observer) }
    background = nil
  }

  /// Takes the picker off the screen, when it is on it, and then runs `afterwards`.
  private func close(_ picker: PHPickerViewController?, afterwards: @escaping () -> Void) {
    guard let picker = picker, picker.presentingViewController != nil else {
      afterwards()
      return
    }
    picker.dismiss(animated: true, completion: afterwards)
  }
}
