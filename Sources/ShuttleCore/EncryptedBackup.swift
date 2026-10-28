import Foundation
import CryptoKit
import CommonCrypto
import Security
import Darwin

/// Version 1: UTF-8 "ShuttleNextBackup\0", one version byte, 32-byte salt,
/// then AES.GCM's combined 12-byte nonce, ciphertext and 16-byte tag.
/// The entire prefix through the salt is authenticated as additional data.
/// The 256-bit key uses PBKDF2-HMAC-SHA256 with exactly 600,000 rounds.
public enum EncryptedBackup {
    private static let magic = Data("ShuttleNextBackup\0".utf8)
    private static let version: UInt8 = 1
    private static let maximumFileBytes = 64 * 1024 * 1024
    private static let maximumContentBytes = 32 * 1024 * 1024
    private static let maximumKeyBytes = 1024 * 1024
    private static let maximumEntries = 10_000
    private static let headerBytes = magic.count + 1 + 32

    private struct Payload: Codable {
        let version: Int
        let entries: [Entry]

        private enum CodingKeys: String, CodingKey { case version, entries }

        init(version: Int, entries: [Entry]) {
            self.version = version
            self.entries = entries
        }

        init(from decoder: Decoder) throws {
            let fields = try decoder.container(keyedBy: CodingKeys.self)
            let version = try fields.decode(Int.self, forKey: .version)
            guard version == Int(EncryptedBackup.version) else { throw EncryptedBackup.invalidContents() }
            var values = try fields.nestedUnkeyedContainer(forKey: .entries)
            if let count = values.count, count > EncryptedBackup.maximumEntries {
                throw EncryptedBackup.invalidContents()
            }
            var entries: [Entry] = []
            entries.reserveCapacity(values.count ?? 0)
            while !values.isAtEnd {
                guard entries.count < EncryptedBackup.maximumEntries else {
                    throw EncryptedBackup.invalidContents()
                }
                entries.append(try values.decode(Entry.self))
            }
            self.init(version: version, entries: entries)
        }
    }

    private struct Entry: Codable {
        let profile: ServerProfile
        let password: String?
        let privateKey: Data?
    }

    public static func isBackup(at url: URL) throws -> Bool {
        let prefix = try readRegularFile(at: url, maximumBytes: maximumFileBytes,
                                         prefixBytes: magic.count, failure: unreadableBackup())
        return prefix == magic
    }

    public static func exportProfiles(_ profiles: [ServerProfile], password: String, to url: URL,
                                      passwordFor: (UUID) throws -> String?) throws {
        try validatePassword(password, exporting: true)
        guard profiles.count <= maximumEntries else { throw invalidContents() }
        guard url.isFileURL, !url.path.utf8.contains(0) else {
            throw ShuttleError.storage("Choose a local file for the export.")
        }
        var identifiers = Set<UUID>()
        var contentBytes = 0
        let normalized = try profiles.map { original in
            try Task.checkCancellation()
            guard identifiers.insert(original.id).inserted else { throw invalidContents() }
            // Bound the original text before normalization can allocate trimmed copies.
            try countContent(of: original, into: &contentBytes)
            return try original.validated()
        }
        try rejectSourceDestination(url, profiles: normalized)
        var entries: [Entry] = []
        entries.reserveCapacity(normalized.count)
        for profile in normalized {
            try Task.checkCancellation()
            let savedPassword: String?
            if profile.passwordMode == .keychain {
                do { savedPassword = try passwordFor(profile.id) }
                catch { throw missingCredential() }
                guard let savedPassword, !savedPassword.isEmpty else { throw missingCredential() }
                try count(savedPassword, into: &contentBytes)
            } else {
                savedPassword = nil
            }
            let privateKey: Data?
            if profile.identity == .privateKey {
                let keyURL = try absoluteKeyURL(profile.identityFile)
                let bytes = try readRegularFile(at: keyURL, maximumBytes: maximumKeyBytes,
                                                failure: unreadableKey())
                try validateKey(bytes)
                try count(bytes.count, into: &contentBytes)
                privateKey = bytes
            } else {
                privateKey = nil
            }
            entries.append(Entry(profile: profile, password: savedPassword, privateKey: privateKey))
        }
        let plaintext: Data
        do { plaintext = try JSONEncoder().encode(Payload(version: Int(version), entries: entries)) }
        catch { throw invalidContents() }
        guard plaintext.count <= maximumFileBytes - headerBytes - 28 else { throw oversized() }
        var salt = Data(count: 32)
        let randomStatus = salt.withUnsafeMutableBytes { bytes in
            SecRandomCopyBytes(kSecRandomDefault, bytes.count, bytes.baseAddress!)
        }
        guard randomStatus == errSecSuccess else { throw encryptionFailed() }
        var header = magic
        header.append(version)
        header.append(salt)
        let key = try deriveKey(password: password, salt: salt)
        try Task.checkCancellation()
        let sealed: AES.GCM.SealedBox
        do { sealed = try AES.GCM.seal(plaintext, using: key, authenticating: header) }
        catch { throw encryptionFailed() }
        guard let combined = sealed.combined else { throw encryptionFailed() }
        var encrypted = header
        encrypted.append(combined)
        try Task.checkCancellation()
        try PrivateAtomicFile.write(encrypted, to: url)
    }

    public static func importProfiles(from url: URL, password: String) throws -> ImportResult {
        try validatePassword(password, exporting: false)
        let encrypted = try readRegularFile(at: url, maximumBytes: maximumFileBytes, failure: unreadableBackup())
        guard encrypted.count >= headerBytes + 28,
              encrypted.prefix(magic.count) == magic,
              encrypted[magic.count] == version else { throw unlockFailed() }
        let header = Data(encrypted.prefix(headerBytes))
        let salt = Data(header.suffix(32))
        let key = try deriveKey(password: password, salt: salt)
        try Task.checkCancellation()
        let plaintext: Data
        do {
            let box = try AES.GCM.SealedBox(combined: encrypted.suffix(from: headerBytes))
            plaintext = try AES.GCM.open(box, using: key, authenticating: header)
        } catch { throw unlockFailed() }
        let payload: Payload
        do { payload = try JSONDecoder().decode(Payload.self, from: plaintext) }
        catch { throw invalidContents() }
        var identifiers = Set<UUID>()
        var contentBytes = 0
        var candidates: [ImportCandidate] = []
        candidates.reserveCapacity(payload.entries.count)
        var automaticIdentity = false
        var hasKeys = false
        var hasConfiguration = false
        for entry in payload.entries {
            try Task.checkCancellation()
            guard identifiers.insert(entry.profile.id).inserted,
                  (entry.profile.passwordMode == .keychain) == (entry.password != nil),
                  (entry.profile.identity == .privateKey) == (entry.privateKey != nil),
                  entry.password?.isEmpty != true else { throw invalidContents() }
            try countContent(of: entry.profile, into: &contentBytes)
            var profile: ServerProfile
            do { profile = try entry.profile.validated() }
            catch { throw invalidContents() }
            // Reject inconsistent metadata rather than silently discarding authenticated fields.
            guard profile == entry.profile else { throw invalidContents() }
            if let password = entry.password { try count(password, into: &contentBytes) }
            if let bytes = entry.privateKey {
                do { try validateKey(bytes) }
                catch { throw invalidContents() }
                try count(bytes.count, into: &contentBytes)
                hasKeys = true
            }
            // An archive identifier must never address credentials already on this Mac.
            profile.id = UUID()
            let needsConfiguration = profile.sshConfigPath != nil
            hasConfiguration = hasConfiguration || needsConfiguration
            automaticIdentity = automaticIdentity || profile.identity == .automatic
            candidates.append(ImportCandidate(profile: profile, password: entry.password,
                                              privateKey: entry.privateKey,
                                              requiresSSHConfiguration: needsConfiguration))
        }
        var warnings: [LocalizedStringResource] = [
            "Encrypted backup unlocked. Selected connections restore their bundled passwords and private keys; application settings are not changed."
        ]
        if hasKeys {
            warnings.append("Bundled encrypted private keys remain encrypted and still require their own passphrases. Key passphrases are not stored in this backup.")
        }
        if automaticIdentity {
            warnings.append("Automatic SSH identities, SSH agents, default keys and hardware devices are external dependencies and are not bundled. Configure them on this Mac before connecting.")
        }
        if hasConfiguration {
            warnings.append("SSH configuration files and their dependencies are not bundled. Choose and trust a configuration on this Mac for each marked connection before importing it.")
        }
        return ImportResult(candidates: candidates, warnings: warnings, isEncryptedBackup: true)
    }

    private static func validatePassword(_ password: String, exporting: Bool) throws {
        guard !password.isEmpty, password.utf8.prefix(1025).count <= 1024,
              !exporting || password.count >= 12 else {
            throw ShuttleError.invalidProfile("Use at least 12 characters for a new backup password, and no more than 1024 UTF-8 bytes. To unlock a backup, enter its original password without changing spaces.")
        }
    }

    private static func deriveKey(password: String, salt: Data) throws -> SymmetricKey {
        var derived = Data(count: 32)
        let passwordByteCount = password.utf8.count
        let status = derived.withUnsafeMutableBytes { output in
            salt.withUnsafeBytes { saltBytes in
                password.withCString { passwordBuffer in
                    CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),
                                        passwordBuffer, passwordByteCount,
                                        saltBytes.baseAddress!.assumingMemoryBound(to: UInt8.self), saltBytes.count,
                                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), 600_000,
                                        output.baseAddress!.assumingMemoryBound(to: UInt8.self), output.count)
                }
            }
        }
        guard status == kCCSuccess else { throw encryptionFailed() }
        return SymmetricKey(data: derived)
    }

    private static func countContent(of profile: ServerProfile, into total: inout Int) throws {
        try count(profile.name, into: &total)
        try count(profile.host, into: &total)
        try count(profile.user, into: &total)
        try count(profile.group, into: &total)
        try count(profile.identityFile, into: &total)
        if let path = profile.sshConfigPath { try count(path, into: &total) }
        try count(profile.notes, into: &total)
    }

    private static func count(_ string: String, into total: inout Int) throws {
        try count(string.utf8.prefix(maximumContentBytes - total + 1).count, into: &total)
    }

    private static func count(_ bytes: Int, into total: inout Int) throws {
        guard bytes <= maximumContentBytes - total else { throw oversized() }
        total += bytes
    }

    private static func validateKey(_ bytes: Data) throws {
        guard bytes.count <= maximumKeyBytes, let text = String(data: bytes, encoding: .utf8) else {
            throw unreadableKey()
        }
        do { _ = try PrivateKeyFileStore.normalizedKey(text) }
        catch { throw unreadableKey() }
    }

    private static func absoluteKeyURL(_ path: String) throws -> URL {
        let expanded = (path as NSString).expandingTildeInPath
        guard expanded.hasPrefix("/"), !expanded.utf8.contains(0) else {
            throw ShuttleError.invalidProfile("Choose an absolute private-key file path before creating an encrypted backup. Relative paths cannot be backed up safely.")
        }
        return URL(fileURLWithPath: expanded)
    }

    private static func rejectSourceDestination(_ destination: URL, profiles: [ServerProfile]) throws {
        let resolvedDestination = destination.resolvingSymlinksInPath().standardizedFileURL.path
        var destinationInfo = stat()
        let existing = stat(destination.path, &destinationInfo) == 0
        for profile in profiles {
            var sources: [URL] = []
            if profile.identity == .privateKey { sources.append(try absoluteKeyURL(profile.identityFile)) }
            if let path = profile.sshConfigPath { sources.append(URL(fileURLWithPath: path)) }
            for source in sources {
                var sourceInfo = stat()
                let sameInode = existing && stat(source.path, &sourceInfo) == 0
                    && sourceInfo.st_dev == destinationInfo.st_dev && sourceInfo.st_ino == destinationInfo.st_ino
                guard !sameInode,
                      source.resolvingSymlinksInPath().standardizedFileURL.path != resolvedDestination else {
                    throw ShuttleError.storage("Choose a backup destination other than a referenced private key or SSH configuration. Source files have not been changed.")
                }
            }
        }
    }

    /// O_NONBLOCK prevents FIFOs from blocking before fstat; O_NOFOLLOW rejects symlink inputs.
    /// Prefix detection reads only the magic bytes, never the full encrypted file.
    private static func readRegularFile(at url: URL, maximumBytes: Int, prefixBytes: Int? = nil,
                                        failure: ShuttleError) throws -> Data {
        guard url.isFileURL, !url.path.utf8.contains(0) else { throw failure }
        let descriptor = open(url.path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw failure }
        defer { close(descriptor) }
        var info = stat()
        guard fstat(descriptor, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
              info.st_size >= 0, info.st_size <= maximumBytes else { throw failure }
        let bound = prefixBytes ?? (maximumBytes + 1)
        var result = Data()
        var buffer = [UInt8](repeating: 0, count: min(16 * 1024, bound))
        while result.count < bound {
            let count = buffer.withUnsafeMutableBytes { bytes in
                Darwin.read(descriptor, bytes.baseAddress!, min(bytes.count, bound - result.count))
            }
            if count < 0 && errno == EINTR { continue }
            guard count >= 0 else { throw failure }
            if count == 0 { break }
            guard count <= maximumBytes - result.count else { throw failure }
            result.append(contentsOf: buffer.prefix(count))
        }
        return result
    }

    private static func unreadableBackup() -> ShuttleError {
        .importFailure("Choose a readable regular encrypted backup file no larger than 64 MiB. Symbolic links and special files are not supported. Nothing was imported.")
    }

    private static func unreadableKey() -> ShuttleError {
        .invalidProfile("Every selected private key must be a readable regular OpenSSH or PEM private-key file no larger than 1 MiB. Symbolic links and unsupported keys cannot be backed up. Nothing was exported.")
    }

    private static func missingCredential() -> ShuttleError {
        .credentials("A saved server password is missing or could not be read from Keychain. Unlock and authorize Keychain access, or save the missing password before backing up. Nothing was exported.")
    }

    private static func invalidContents() -> ShuttleError {
        .importFailure("The encrypted backup contains invalid, inconsistent or unsupported connection data. Nothing was imported or exported.")
    }

    private static func oversized() -> ShuttleError {
        .storage("The backup exceeds the 64 MiB encrypted-file limit or the 32 MiB combined connection, password and private-key content limit. Nothing was imported or exported.")
    }

    private static func unlockFailed() -> ShuttleError {
        .importFailure("The backup could not be unlocked. Check its password and use an intact supported encrypted backup. Nothing was imported.")
    }

    private static func encryptionFailed() -> ShuttleError {
        .storage("The encrypted backup could not be secured. No backup file was changed.")
    }
}
