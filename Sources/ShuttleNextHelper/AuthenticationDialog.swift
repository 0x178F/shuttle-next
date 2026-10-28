import AppKit
import Foundation
import ShuttleCore

struct AuthenticationCancelled: Error {}

@MainActor
enum AuthenticationDialog {
    enum Request {
        case hostConfirmation
        case secret
    }

    static func request(for prompt: String, hint: String?) throws -> Request {
        // Reject changed-key challenges even if OpenSSH unexpectedly asks.
        if prompt.localizedCaseInsensitiveContains("REMOTE HOST IDENTIFICATION HAS CHANGED") {
            throw ShuttleError.connection("The server's host key changed. SSH rejected this connection.")
        }
        if hint == "confirm" || prompt.contains("Are you sure you want to continue connecting") {
            return .hostConfirmation
        }
        return .secret
    }

    // Automatic Keychain responses are resolved before entering any modal runloop.
    static func response(to prompt: String, request: Request, profile: ServerProfile,
                         session: AskpassSession, localizer: AppLocalizer) throws -> String {
        switch request {
        case .hostConfirmation:
            return try confirmHost(prompt: prompt, profile: profile, session: session, localizer: localizer)
        case .secret:
            return try secureResponse(prompt: prompt, profile: profile, session: session, localizer: localizer)
        }
    }


    private static func prepareApplication() {
        let app = NSApplication.shared
        app.setActivationPolicy(.accessory)
        app.activate(ignoringOtherApps: true)
    }

    private static func confirmHost(prompt: String, profile: ServerProfile,
                                    session: AskpassSession, localizer: AppLocalizer) throws -> String {
        prepareApplication()
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = localizer.text("Verify the SSH host key")
        alert.informativeText = localizer.text("Connection: \(profile.name)\n\n\(displayPrompt(prompt))\n\nCompare the fingerprint with a trusted source. Connect only if it matches.")
        alert.addButton(withTitle: localizer.text("Connect"))
        alert.addButton(withTitle: localizer.text("Cancel"))
        // Return must not accidentally accept a new host while typing.
        alert.buttons[0].keyEquivalent = ""
        alert.buttons[1].keyEquivalent = "\r"
        guard try runModal(alert, session: session) == .alertFirstButtonReturn else {
            throw AuthenticationCancelled()
        }
        return "yes"
    }

    private static func secureResponse(prompt: String, profile: ServerProfile,
                                       session: AskpassSession, localizer: AppLocalizer) throws -> String {
        prepareApplication()
        let alert = NSAlert()
        alert.messageText = localizer.text("SSH authentication")
        alert.informativeText = localizer.text("Connection: \(profile.name)\n\n\(displayPrompt(prompt))")
        let input = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 360, height: 24))
        input.placeholderString = localizer.text("Password, passphrase, or verification response")
        alert.accessoryView = input
        alert.addButton(withTitle: localizer.text("Continue"))
        alert.addButton(withTitle: localizer.text("Cancel"))
        alert.window.initialFirstResponder = input
        defer { input.stringValue = "" }
        guard try runModal(alert, session: session) == .alertFirstButtonReturn else {
            throw AuthenticationCancelled()
        }
        let value = input.stringValue
        guard !value.contains("\n"), !value.contains("\r"), !value.contains("\0") else {
            throw ShuttleError.connection("The authentication response contains a character that SSH askpass cannot submit.")
        }
        return value
    }

    private static func runModal(_ alert: NSAlert, session: AskpassSession) throws -> NSApplication.ModalResponse {
        guard !session.isCancelled else { throw AuthenticationCancelled() }
        let cancellationMonitor = Timer(timeInterval: 0.1, repeats: true) { _ in
            MainActor.assumeIsolated {
                if session.isCancelled {
                    NSApplication.shared.abortModal()
                    alert.window.orderOut(nil)
                }
            }
        }
        RunLoop.main.add(cancellationMonitor, forMode: .modalPanel)
        defer { cancellationMonitor.invalidate() }
        let response = alert.runModal()
        guard !session.isCancelled else { throw AuthenticationCancelled() }
        return response
    }

    private static func displayPrompt(_ prompt: String) -> String {
        let controlCharacters = CharacterSet.controlCharacters
        return String(String.UnicodeScalarView(prompt.unicodeScalars.lazy.filter {
            !controlCharacters.contains($0) || $0 == "\n" || $0 == "\t"
        }.prefix(8_192)))
    }

}
