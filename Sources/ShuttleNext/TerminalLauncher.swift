import AppKit
import Foundation
import ShuttleCore

struct TerminalLauncher {
    static func applicationURL(for terminal: TerminalChoice) -> URL? {
        guard let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: terminal.bundleIdentifier),
              FileManager.default.isExecutableFile(atPath: Bundle(url: url)?.executableURL?.path ?? "") else { return nil }
        return url
    }

    static func availableTerminals() -> [TerminalChoice] {
        TerminalChoice.allCases.filter { applicationURL(for: $0) != nil }
    }

    static func launch(profileID: UUID, library: URL, settings: AppSettings) throws {
        guard let application = applicationURL(for: settings.terminal) else {
            throw ShuttleError.connection("\(settings.terminal.title) is not installed. Open Settings and choose an available terminal.")
        }
        guard let appExecutable = Bundle.main.executableURL else { throw ShuttleError.connection("The application’s executable could not be located.") }
        let helper = appExecutable.deletingLastPathComponent().appendingPathComponent("ShuttleNextHelper")
        guard FileManager.default.isExecutableFile(atPath: helper.path) else {
            throw ShuttleError.connection("The bundled SSH helper is missing. Run scripts/build-app.sh and open the generated ShuttleNext.app.")
        }
        let helperArguments = [helper.path, "--connect", profileID.uuidString, "--library", library.path]
        let scripted = settings.terminal == .terminal || settings.terminal == .iTerm
        let process = Process()
        process.executableURL = URL(fileURLWithPath: scripted ? "/usr/bin/osascript" : "/usr/bin/open")
        switch settings.terminal {
        case .terminal, .iTerm:
            let command = helperArguments.map(SSHCommand.shellQuote).joined(separator: " ")
            let script: String
            if settings.terminal == .terminal {
                script = """
                on run argv
                    set connectionCommand to item 1 of argv
                    tell application id "com.apple.Terminal"
                        activate
                        do script connectionCommand
                    end tell
                end run
                """
            } else {
                script = """
                on run argv
                    set connectionCommand to item 1 of argv
                    set openingMode to item 2 of argv
                    tell application id "com.googlecode.iterm2"
                        activate
                        if openingMode is "tab" and (count of windows) > 0 then
                            tell current window
                                set targetTab to (create tab with default profile)
                            end tell
                            tell current session of targetTab to write text connectionCommand
                        else
                            set targetWindow to (create window with default profile)
                            tell current session of targetWindow to write text connectionCommand
                        end if
                    end tell
                end run
                """
            }
            process.arguments = ["-e", script, "--", command, settings.openMode.rawValue]
        case .ghostty, .alacritty:
            // LaunchServices detaches the GUI; -n ensures command arguments are delivered.
            process.arguments = ["-n", "-a", application.path, "--args", "-e"] + helperArguments
        case .kitty:
            process.arguments = ["-n", "-a", application.path, "--args", "--single-instance", "--session", "none", "--"] + helperArguments
        case .wezTerm:
            var arguments = ["-n", "-a", application.path, "--args", "start"]
            if settings.openMode == .tab { arguments.append("--new-tab") }
            arguments += ["--"] + helperArguments
            process.arguments = arguments
        }
        process.standardOutput = FileHandle.nullDevice
        let errors = Pipe()
        process.standardError = errors
        try process.run()
        let deadline = DispatchWorkItem { if process.isRunning { process.terminate() } }
        DispatchQueue.global().asyncAfter(deadline: .now() + 60, execute: deadline)
        let data = errors.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        deadline.cancel()
        guard process.terminationStatus == 0 else {
            let details = String(decoding: data.prefix(4096), as: UTF8.self)
            if scripted && (details.contains("-1743") || details.localizedCaseInsensitiveContains("not authorized")) {
                throw ShuttleError.connection("macOS has not allowed ShuttleNext to control your terminal. Enable it in System Settings → Privacy & Security → Automation, then try again.")
            }
            throw ShuttleError.connection("The terminal could not be opened. \(details.trimmingCharacters(in: .whitespacesAndNewlines))")
        }
    }
}
