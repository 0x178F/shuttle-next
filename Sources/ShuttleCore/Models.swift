import Foundation

public enum SSHIdentity: String, Codable, Sendable {
    case automatic, privateKey, none
}

public enum ServerPasswordMode: String, Codable, Sendable {
    case askWhenNeeded, keychain
}

public enum TerminalChoice: String, Codable, CaseIterable, Sendable, Identifiable {
    case terminal, iTerm, ghostty, kitty, alacritty, wezTerm
    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .terminal: "Terminal.app"
        case .iTerm: "iTerm2"
        case .ghostty: "Ghostty"
        case .kitty: "kitty"
        case .alacritty: "Alacritty"
        case .wezTerm: "WezTerm"
        }
    }

    public var bundleIdentifier: String {
        switch self {
        case .terminal: "com.apple.Terminal"
        case .iTerm: "com.googlecode.iterm2"
        case .ghostty: "com.mitchellh.ghostty"
        case .kitty: "net.kovidgoyal.kitty"
        case .alacritty: "org.alacritty"
        case .wezTerm: "com.github.wez.wezterm"
        }
    }

    public var supportsTabs: Bool { self == .iTerm || self == .wezTerm }
}

public enum TerminalOpenMode: String, Codable, CaseIterable, Sendable, Identifiable {
    case window, tab
    public var id: String { rawValue }
}

public struct AppSettings: Codable, Equatable, Sendable {
    public var terminal: TerminalChoice
    public var openMode: TerminalOpenMode
    public var globalShortcutEnabled: Bool
    public var language: AppLanguage
    public init(terminal: TerminalChoice = .terminal, openMode: TerminalOpenMode = .window, globalShortcutEnabled: Bool = false,
                language: AppLanguage = .system) {
        self.terminal = terminal
        self.openMode = openMode
        self.globalShortcutEnabled = globalShortcutEnabled
        self.language = language
    }

    private enum CodingKeys: String, CodingKey { case terminal, openMode, globalShortcutEnabled, language }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        terminal = try values.decode(TerminalChoice.self, forKey: .terminal)
        openMode = try values.decode(TerminalOpenMode.self, forKey: .openMode)
        globalShortcutEnabled = try values.decode(Bool.self, forKey: .globalShortcutEnabled)
        let identifier = try values.decodeIfPresent(String.self, forKey: .language)
        language = identifier.flatMap(AppLanguage.init(rawValue:)) ?? .system
    }
}

public struct ServerProfile: Codable, Hashable, Identifiable, Sendable {
    public var id: UUID
    public var name: String
    public var host: String
    public var user: String
    public var port: Int?
    public var group: String
    public var identity: SSHIdentity
    public var passwordMode: ServerPasswordMode
    public var identityFile: String
    public var isFavorite: Bool
    public var sshConfigPath: String?
    public var notes: String

    public init(id: UUID = UUID(), name: String = "", host: String = "", user: String = "", port: Int? = nil,
                group: String = "", identity: SSHIdentity = .automatic,
                passwordMode: ServerPasswordMode = .askWhenNeeded, identityFile: String = "",
                isFavorite: Bool = false, sshConfigPath: String? = nil, notes: String = "") {
        self.id = id; self.name = name; self.host = host; self.user = user; self.port = port
        self.group = group; self.identity = identity; self.passwordMode = passwordMode; self.identityFile = identityFile
        self.isFavorite = isFavorite; self.sshConfigPath = sshConfigPath; self.notes = notes
    }

    public var destination: String { user.isEmpty ? host : "\(user)@\(host)" }

    private static let allowedHostCharacters = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-:%[]")
    private static let allowedUserCharacters = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-\\")

    public func validated() throws -> ServerProfile {
        var result = self
        result.name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        result.host = host.trimmingCharacters(in: .whitespacesAndNewlines)
        result.user = user.trimmingCharacters(in: .whitespacesAndNewlines)
        result.group = group.trimmingCharacters(in: .whitespacesAndNewlines)
        result.identityFile = identityFile.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !result.name.isEmpty else { throw ShuttleError.invalidProfile("Enter a server name.") }
        guard !result.host.isEmpty, !result.host.hasPrefix("-"), result.host.unicodeScalars.allSatisfy(Self.allowedHostCharacters.contains) else {
            throw ShuttleError.invalidProfile("Enter a hostname, SSH alias, or IP address without a username or spaces.")
        }
        guard result.user.unicodeScalars.allSatisfy(Self.allowedUserCharacters.contains), !result.user.hasPrefix("-") else {
            throw ShuttleError.invalidProfile("Use a username containing letters, numbers, dots, underscores, hyphens, or a domain backslash; it cannot start with a dash.")
        }
        if let port = result.port, !(1...65535).contains(port) { throw ShuttleError.invalidProfile("Port must be between 1 and 65535.") }
        if result.identity == .privateKey && result.identityFile.isEmpty {
            throw ShuttleError.invalidProfile("Choose a private key file.")
        }
        let controlCharacters = CharacterSet.controlCharacters
        guard !result.identityFile.unicodeScalars.contains(where: { controlCharacters.contains($0) }) else {
            throw ShuttleError.invalidProfile("The identity-file path contains a control character.")
        }
        if result.identity != .privateKey { result.identityFile = "" }
        if let path = result.sshConfigPath, (!path.hasPrefix("/") || path.unicodeScalars.contains(where: { controlCharacters.contains($0) })) {
            throw ShuttleError.invalidProfile("The imported SSH configuration must use an absolute path.")
        }
        return result
    }
}

public struct LibraryDocument: Codable, Equatable, Sendable {
    public static let currentVersion = 2
    public var version: Int
    public var profiles: [ServerProfile]
    public var settings: AppSettings
    public init(version: Int = LibraryDocument.currentVersion, profiles: [ServerProfile] = [], settings: AppSettings = AppSettings()) {
        self.version = version; self.profiles = profiles; self.settings = settings
    }

    private enum CodingKeys: String, CodingKey { case version, profiles, settings }

    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        let version = try values.decode(Int.self, forKey: .version)
        let profiles: [ServerProfile]
        switch version {
        case 1:
            profiles = try values.decode([LegacyProfile].self, forKey: .profiles).map(\.migrated)
        case Self.currentVersion:
            profiles = try values.decode([ServerProfile].self, forKey: .profiles)
        default:
            throw ShuttleError.storage("This library uses an unsupported format version. It has not been overwritten.")
        }
        self.init(profiles: profiles, settings: try values.decode(AppSettings.self, forKey: .settings))
    }

    private struct LegacyProfile: Decodable {
        enum Method: String, Decodable { case automatic, privateKey, password, askEveryTime }
        let id: UUID
        let name: String
        let host: String
        let user: String
        let port: Int?
        let group: String
        let authentication: Method
        let identityFile: String
        let isFavorite: Bool
        let sshConfigPath: String?
        let notes: String

        var migrated: ServerProfile {
            let identity: SSHIdentity
            switch authentication {
            case .automatic: identity = identityFile.isEmpty ? .automatic : .privateKey
            case .privateKey: identity = .privateKey
            case .password: identity = identityFile.isEmpty ? .none : .privateKey
            case .askEveryTime: identity = .none
            }
            return ServerProfile(id: id, name: name, host: host, user: user, port: port, group: group,
                                 identity: identity, passwordMode: authentication == .password ? .keychain : .askWhenNeeded,
                                 identityFile: identityFile, isFavorite: isFavorite, sshConfigPath: sshConfigPath, notes: notes)
        }
    }
}

public struct ImportCandidate: Identifiable, Sendable {
    public var profile: ServerProfile
    /// Never encode this imported password into the library or logs.
    public var password: String?
    public var id: UUID { profile.id }
    /// Bundled private key bytes live only in memory until explicitly restored.
    public var privateKey: Data?
    public var requiresSSHConfiguration: Bool
    public init(profile: ServerProfile, password: String? = nil, privateKey: Data? = nil,
                requiresSSHConfiguration: Bool = false) {
        self.profile = profile
        self.password = password
        self.privateKey = privateKey
        self.requiresSSHConfiguration = requiresSSHConfiguration
    }
}

public struct ImportResult: Sendable {
    public var candidates: [ImportCandidate]
    public var warnings: [LocalizedStringResource]
    public var isEncryptedBackup: Bool
    public init(candidates: [ImportCandidate] = [], warnings: [LocalizedStringResource] = [],
                isEncryptedBackup: Bool = false) {
        self.candidates = candidates
        self.warnings = warnings
        self.isEncryptedBackup = isEncryptedBackup
    }
}

public enum ShuttleError: LocalizedError {
    case invalidProfile(LocalizedStringResource)
    case storage(LocalizedStringResource)
    case credentials(LocalizedStringResource)
    case importFailure(LocalizedStringResource)
    case connection(LocalizedStringResource)

    public var message: LocalizedStringResource {
        switch self {
        case .invalidProfile(let message), .storage(let message), .credentials(let message),
             .importFailure(let message), .connection(let message): return message
        }
    }

    public var errorDescription: String? {
        AppLocalizer().text(message)
    }
}
