//
//  Where a device check leaves its results.
//
//  A test driving the application can read an accessibility element by its identifier, so each
//  result is one: a point-sized view in the application's own window, transparent enough to change
//  nothing a person sees, outside every layout, carrying its result as its accessibility value.
//  Compiled into debug builds only.
//

#if DEBUG
import UIKit

/// The results a check has to show.
final class ProbeSurface {
    static let shared = ProbeSurface()

    private var elements: [String: UIView] = [:]

    /// Shows `value` as the result named `name`, creating its element the first time.
    func show(_ name: String, _ value: String) {
        DispatchQueue.main.async {
            self.element(named: name).accessibilityValue = value
        }
    }

    private func element(named name: String) -> UIView {
        if let existing = elements[name] { return existing }
        let view = UIView(frame: CGRect(x: CGFloat(elements.count * 2), y: 0, width: 1, height: 1))
        view.isAccessibilityElement = true
        view.accessibilityIdentifier = "kr.probe.\(name)"
        view.accessibilityLabel = "probe \(name)"
        view.alpha = 0.02
        view.isUserInteractionEnabled = false
        elements[name] = view
        attach(view)
        return view
    }

    /// Puts an element in the application's window, waiting for the window when it is not there yet.
    private func attach(_ view: UIView, tries: Int = 0) {
        if let window = ProbeSurface.keyWindow() {
            window.addSubview(view)
            return
        }
        guard tries < 100 else { return }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) { self.attach(view, tries: tries + 1) }
    }

    /// The application's main window.
    static func keyWindow() -> UIWindow? {
        UIApplication.shared.windows.first(where: { $0.isKeyWindow }) ?? UIApplication.shared.windows.first
    }
}
#endif
