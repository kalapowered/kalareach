import AVFoundation
import CompanionScan
import PhotosUI
import UIKit
import UniformTypeIdentifiers

/// What reading a code came to: the text of the code, that the person closed the scanner or the
/// picker, that a picture showed no code, or that the camera is not allowed.
enum ScanOutcome {
  case text(String)
  case cancelled
  case noCode
  case cameraDenied
}

/// The one answer a request to read a code gets, in the words the plugin's Rust half reads.
struct ScanAnswer: Encodable {
  let outcome: String
  var text: String? = nil

  init(_ outcome: ScanOutcome) {
    switch outcome {
    case .text(let found):
      self.outcome = "text"
      self.text = found
    case .cancelled: self.outcome = "cancelled"
    case .noCode: self.outcome = "no_code"
    case .cameraDenied: self.outcome = "camera_denied"
    }
  }
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
  private var found = false
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
      presenter.present(scanner, animated: true)
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
    configureCamera()
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
    center.addObserver(
      self, selector: #selector(cancelTapped), name: UIApplication.didEnterBackgroundNotification, object: nil)
  }

  override func viewDidAppear(_ animated: Bool) {
    super.viewDidAppear(animated)
    frames.async { self.session.startRunning() }
    UIAccessibility.post(notification: .screenChanged, argument: hint)
  }

  override func viewDidLayoutSubviews() {
    super.viewDidLayoutSubviews()
    preview.frame = view.bounds
    let side = min(view.bounds.width, view.bounds.height) * 0.7
    let square = CGRect(
      x: (view.bounds.width - side) / 2, y: (view.bounds.height - side) / 2, width: side, height: side)
    outline.path = UIBezierPath(roundedRect: square, cornerRadius: 24).cgPath
    let margin = view.safeAreaInsets
    hint.frame = CGRect(
      x: 24, y: square.minY - 24 - 60, width: view.bounds.width - 48, height: 60)
    hint.sizeToFit()
    hint.frame = CGRect(
      x: 24, y: square.minY - 24 - hint.bounds.height, width: view.bounds.width - 48, height: hint.bounds.height)
    cancel.frame = CGRect(x: 16, y: margin.top + 8, width: 88, height: 44)
    torch.frame = CGRect(x: view.bounds.width - 16 - 44, y: margin.top + 8, width: 44, height: 44)
  }

  private func configureCamera() {
    guard
      let camera = AVCaptureDevice.default(.builtInWideAngleCamera, for: .video, position: .back)
        ?? AVCaptureDevice.default(for: .video),
      let input = try? AVCaptureDeviceInput(device: camera)
    else { return }
    device = camera
    session.beginConfiguration()
    // A host's direct invitation is a version-23 code, 109 modules wide: it needs more than the
    // default preview resolution to be read from a hand's length.
    session.sessionPreset = session.canSetSessionPreset(.hd1920x1080) ? .hd1920x1080 : .high
    if session.canAddInput(input) { session.addInput(input) }
    let output = AVCaptureVideoDataOutput()
    output.alwaysDiscardsLateVideoFrames = true
    output.setSampleBufferDelegate(self, queue: frames)
    if session.canAddOutput(output) { session.addOutput(output) }
    session.commitConfiguration()
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

  /// What the camera sees is not shown in the application switcher.
  @objc private func hidePreview() { preview.isHidden = true }
  @objc private func showPreview() { preview.isHidden = false }

  /// Ends the scan once, whichever of the person, a code or the system ends it first, and answers
  /// after the scanner has gone from the screen.
  func finish(_ outcome: ScanOutcome) {
    guard !finished else { return }
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
    dismiss(animated: true) { answer?(outcome) }
  }
}

/// The system's picker for one picture. It hands this application only the picture the person
/// chose, and needs no permission to the photo library.
final class PhotoReader: NSObject, PHPickerViewControllerDelegate {
  private var done: ((ScanOutcome) -> Void)?
  private weak var picker: PHPickerViewController?

  /// Ends the pick with a cancel, closing the picker.
  func cancel() {
    let answer = done
    done = nil
    guard let picker = picker else {
      answer?(.cancelled)
      return
    }
    picker.dismiss(animated: true) { answer?(.cancelled) }
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
    presenter.present(picker, animated: true)
  }

  func picker(_ picker: PHPickerViewController, didFinishPicking results: [PHPickerResult]) {
    let answer = done
    done = nil
    guard let provider = results.first?.itemProvider else {
      picker.dismiss(animated: true) { answer?(.cancelled) }
      return
    }
    // The picture is read in memory, and never written anywhere.
    provider.loadDataRepresentation(forTypeIdentifier: UTType.image.identifier) { data, _ in
      let outcome: ScanOutcome = data.flatMap { QrReader.text(in: $0) }.map { .text($0) } ?? .noCode
      DispatchQueue.main.async { picker.dismiss(animated: true) { answer?(outcome) } }
    }
  }
}
