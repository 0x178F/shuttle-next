import Darwin
import Foundation
import MachO
import ShuttleCore


@MainActor
private enum Helper {
    static func run() -> Int32 {
        let environment = ProcessInfo.processInfo.environment
        let isAskpass = environment["SHUTTLENEXT_ASKPASS"] == "1"
        var localizer = AppLocalizer()
        do {
            if isAskpass {
                try answerAskpass(environment: environment, localizer: &localizer)
                return 0
            }
            return try connect(localizer: &localizer)
        } catch is AuthenticationCancelled {
            return 130
        } catch {
            // Only print curated errors; Foundation diagnostics may expose sensitive input.
            let message: String
            if let error = error as? ShuttleError {
                message = localizer.error(error)
            } else {
                message = localizer.text("SSH could not complete the operation. Check the library, executable permissions, and Keychain access.")
            }
            let diagnostic = localizer.text("ShuttleNext: \(message)")
            try? FileHandle.standardError.write(contentsOf: Data((diagnostic + "\n").utf8))
            return 1
        }
    }

    private static func connect(localizer: inout AppLocalizer) throws -> Int32 {
        let arguments = CommandLine.arguments
        guard arguments.count == 5, arguments[1] == "--connect",
              let id = UUID(uuidString: arguments[2]), arguments[3] == "--library" else {
            throw ShuttleError.connection("Usage: ShuttleNextHelper --connect UUID --library /absolute/directory")
        }
        let library = try libraryURL(arguments[4])
        let profile = try loadProfile(id: id, repository: ProfileRepository(directory: library), localizer: &localizer)
        let sshArguments = try SSHCommand.arguments(for: profile)
        let executable = try executableURL()
        let session = try AskpassSession.create(profile: profile, library: library)
        defer { session.remove() }

        var environment = ProcessInfo.processInfo.environment
        environment["SSH_ASKPASS"] = executable.path
        environment["SSH_ASKPASS_REQUIRE"] = "force"
        environment["SHUTTLENEXT_ASKPASS"] = "1"
        environment["SHUTTLENEXT_PROFILE_ID"] = id.uuidString
        environment["SHUTTLENEXT_DATA_DIR"] = library.path
        environment[AskpassSession.environmentKey] = session.directory
        environment.removeValue(forKey: "SSH_ASKPASS_PROMPT")
        environment["LC_ALL"] = "C"
        // Older OpenSSH versions require DISPLAY for askpass, even for native dialogs.
        if environment["DISPLAY", default: ""].isEmpty { environment["DISPLAY"] = "ShuttleNext" }

        return try SSHProcess.run(arguments: sshArguments, environment: environment)
    }

    private static func answerAskpass(environment: [String: String], localizer: inout AppLocalizer) throws {
        guard CommandLine.arguments.count == 2,
              let rawID = environment["SHUTTLENEXT_PROFILE_ID"], let id = UUID(uuidString: rawID),
              let libraryPath = environment["SHUTTLENEXT_DATA_DIR"],
              let directory = environment[AskpassSession.environmentKey] else {
            throw ShuttleError.connection("The SSH authentication request is missing its connection session.")
        }
        // Secret responses must go to OpenSSH's pipe, never a terminal or regular file.
        var outputInfo = stat()
        guard fstat(STDOUT_FILENO, &outputInfo) == 0, (outputInfo.st_mode & S_IFMT) == S_IFIFO else {
            throw ShuttleError.connection("SSH authentication requires a private response pipe.")
        }
        let library = try libraryURL(libraryPath)
        let session = try AskpassSession.load(directory: directory, profileID: id, library: library)
        do {
            guard !session.isCancelled else { throw AuthenticationCancelled() }
            let repository = ProfileRepository(directory: library)
            let prompt = CommandLine.arguments[1]
            guard prompt.utf8.count <= 65_536 else {
                throw ShuttleError.connection("The SSH authentication prompt is too large.")
            }
            let request = try AuthenticationDialog.request(for: prompt, hint: environment["SSH_ASKPASS_PROMPT"])
            let (profile, automaticResponse) = try repository.withCredentialAccess {
                let profile = try loadProfile(id: id, repository: repository, localizer: &localizer)
                try session.validate(profile: profile)
                guard !session.isCancelled else { throw AuthenticationCancelled() }
                let automaticResponse: String?
                if case .secret = request, profile.passwordMode == .keychain, SSHCommand.isPasswordPrompt(prompt) {
                    automaticResponse = try savedPassword(profile: profile, session: session)
                } else {
                    automaticResponse = nil
                }
                return (profile, automaticResponse)
            }
            // Manual dialogs must not prevent library edits or credential cleanup.
            let response: String
            if let automaticResponse {
                response = automaticResponse
            } else {
                response = try AuthenticationDialog.response(to: prompt, request: request,
                                                             profile: profile, session: session, localizer: localizer)
            }
            guard !session.isCancelled else { throw AuthenticationCancelled() }
            try FileHandle.standardOutput.write(contentsOf: Data((response + "\n").utf8))
        } catch {
            // Abort SSH before an askpass failure becomes an empty authentication attempt.
            session.cancelConnection()
            throw error
        }
    }

    private static func savedPassword(profile: ServerProfile, session: AskpassSession) throws -> String {
        try session.claimSavedPassword()
        guard let password = try CredentialStore().password(for: profile.id), !password.isEmpty else {
            throw ShuttleError.connection("No saved password is available in Keychain. Edit this server's password settings in ShuttleNext.")
        }
        guard !password.contains("\n"), !password.contains("\r"), !password.contains("\0") else {
            throw ShuttleError.connection("The saved password contains a character that SSH askpass cannot submit.")
        }
        return password
    }

    private static func loadProfile(id: UUID, repository: ProfileRepository, localizer: inout AppLocalizer) throws -> ServerProfile {
        let document = try repository.load()
        localizer = AppLocalizer(language: document.settings.language)
        guard let profile = document.profiles.first(where: { $0.id == id }) else {
            throw ShuttleError.connection("This server is no longer present in the ShuttleNext library.")
        }
        return profile
    }

    private static func libraryURL(_ path: String) throws -> URL {
        let controlCharacters = CharacterSet.controlCharacters
        guard path.hasPrefix("/"), !path.unicodeScalars.contains(where: { controlCharacters.contains($0) }) else {
            throw ShuttleError.connection("The library directory must be an absolute path without control characters.")
        }
        return URL(fileURLWithPath: path, isDirectory: true).standardizedFileURL.resolvingSymlinksInPath()
    }

    private static func executableURL() throws -> URL {
        // Bundle.main may identify the app executable; dyld identifies this helper.
        var count: UInt32 = 0
        _NSGetExecutablePath(nil, &count)
        guard count > 0 else { throw ShuttleError.connection("The SSH helper could not locate itself.") }
        var buffer = [CChar](repeating: 0, count: Int(count))
        guard _NSGetExecutablePath(&buffer, &count) == 0 else {
            throw ShuttleError.connection("The SSH helper could not locate itself.")
        }
        let url = URL(fileURLWithPath: String(cString: buffer)).standardizedFileURL.resolvingSymlinksInPath()
        guard url.path.hasPrefix("/"), FileManager.default.isExecutableFile(atPath: url.path) else {
            throw ShuttleError.connection("The SSH helper executable is unavailable.")
        }
        return url
    }
}

MainActor.assumeIsolated {
    exit(Helper.run())
}
