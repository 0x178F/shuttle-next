import Foundation
import Darwin
import CryptoKit
import CommonCrypto
import Testing
import ShuttleCore

struct EncryptedBackupTests {
    private let password = "correct backup password  🔐\u{0} "
    private let firstKey = Data("-----BEGIN ENCRYPTED PRIVATE KEY-----\nAQIDBA==\n-----END ENCRYPTED PRIVATE KEY-----\n".utf8)
    private let secondKey = Data("-----BEGIN OPENSSH PRIVATE KEY-----\r\nBQYHCA==\r\n-----END OPENSSH PRIVATE KEY-----\r\n".utf8)

    private func temporaryDirectory() throws -> URL {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("ShuttleNext-backup-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return directory
    }

    @Test func roundTripPreservesPerServerSecretsAndCreatesFreshIdentities() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let keyA = root.appendingPathComponent("first-key")
        let keyB = root.appendingPathComponent("second-key")
        try firstKey.write(to: keyA)
        try secondKey.write(to: keyB)
        let config = root.appendingPathComponent("config-not-bundled")
        let configBytes = Data("Host *\n  ProxyCommand echo CONFIG-CONTENT-EXCLUDED\n".utf8)
        try configBytes.write(to: config)
        let profiles = [
            ServerProfile(name: "First", host: "first.test", user: "alice", port: 2222,
                          group: "Work", identity: .privateKey, passwordMode: .keychain,
                          identityFile: keyA.path, isFavorite: true, sshConfigPath: config.path, notes: "Private note A"),
            ServerProfile(name: "Second", host: "second.test", user: "bob", identity: .privateKey,
                          passwordMode: .keychain, identityFile: keyB.path, notes: "Private note B"),
            ServerProfile(name: "Automatic", host: "automatic.test")
        ]
        let passwords = [profiles[0].id: "password-ALICE-unique", profiles[1].id: "password-BOB-unique"]
        var queried: [UUID] = []
        let backup = root.appendingPathComponent("portable.shuttlenext")
        try EncryptedBackup.exportProfiles(profiles, password: password, to: backup) { id in
            queried.append(id)
            return passwords[id]
        }
        #expect(Set(queried) == Set(profiles.prefix(2).map(\.id)))
        #expect(try EncryptedBackup.isBackup(at: backup))
        let encrypted = try Data(contentsOf: backup)
        for secret in [firstKey, secondKey, configBytes, Data("Private note A".utf8), Data("password-ALICE-unique".utf8)] {
            #expect(encrypted.range(of: secret) == nil)
        }
        let permissions = try #require(FileManager.default.attributesOfItem(atPath: backup.path)[.posixPermissions] as? NSNumber)
        #expect(permissions.intValue & 0o777 == 0o600)
        let result = try EncryptedBackup.importProfiles(from: backup, password: password)
        let again = try EncryptedBackup.importProfiles(from: backup, password: password)
        #expect(result.isEncryptedBackup)
        try #require(result.candidates.count == profiles.count)
        #expect(!result.warnings.isEmpty)
        for (index, candidate) in result.candidates.enumerated() {
            #expect(!profiles.map(\.id).contains(candidate.id))
            #expect(!again.candidates.map(\.id).contains(candidate.id))
            var expected = profiles[index]
            expected.id = candidate.id
            #expect(candidate.profile == expected)
            #expect(candidate.password == passwords[profiles[index].id])
        }
        #expect(result.candidates[0].privateKey == firstKey)
        #expect(result.candidates[1].privateKey == secondKey)
        #expect(result.candidates[2].privateKey == nil)
        #expect(result.candidates[0].requiresSSHConfiguration)
        #expect(!result.candidates[1].requiresSSHConfiguration)
        #expect(try Data(contentsOf: keyA) == firstKey)
        #expect(try Data(contentsOf: keyB) == secondKey)
        #expect(try Data(contentsOf: config) == configBytes)
        #expect(try FileManager.default.contentsOfDirectory(atPath: root.path).count == 4)
    }

    @Test func encryptionUsesFreshSaltAndNonceAndAuthenticatesAllEnvelopeRegions() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let first = root.appendingPathComponent("first")
        let second = root.appendingPathComponent("second")
        let profiles = [ServerProfile(name: "Secret server", host: "secret.test")]
        try EncryptedBackup.exportProfiles(profiles, password: password, to: first) { _ in nil }
        try EncryptedBackup.exportProfiles(profiles, password: password, to: second) { _ in nil }
        let original = try Data(contentsOf: first)
        let other = try Data(contentsOf: second)
        #expect(original != other)
        #expect(original[19..<51] != other[19..<51])
        #expect(original[51..<63] != other[51..<63])
        #expect(throws: ShuttleError.self) { try EncryptedBackup.importProfiles(from: first, password: "wrong password") }
        #expect(throws: ShuttleError.self) { try EncryptedBackup.importProfiles(from: first, password: password.trimmingCharacters(in: .whitespaces)) }
        for index in [0, 18, 19, 51, original.count - 1] {
            var corrupt = original
            corrupt[index] ^= 1
            try corrupt.write(to: second)
            #expect(throws: ShuttleError.self) { try EncryptedBackup.importProfiles(from: second, password: password) }
        }
        try original.prefix(60).write(to: second)
        #expect(throws: ShuttleError.self) { try EncryptedBackup.importProfiles(from: second, password: password) }
        #expect(try Data(contentsOf: first) == original)
        #expect(try FileManager.default.contentsOfDirectory(atPath: root.path).count == 2)
    }

    @Test func incompleteCaptureNeverReplacesExistingDestinationOrSources() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let destination = root.appendingPathComponent("existing")
        let original = Data("preserve-existing-destination".utf8)
        try original.write(to: destination)
        let key = root.appendingPathComponent("key")
        try firstKey.write(to: key)
        let profile = ServerProfile(name: "Saved", host: "saved.test", identity: .privateKey,
                                    passwordMode: .keychain, identityFile: key.path)
        #expect(throws: ShuttleError.self) {
            try EncryptedBackup.exportProfiles([profile], password: password, to: destination) { _ in nil }
        }
        #expect(throws: ShuttleError.self) {
            try EncryptedBackup.exportProfiles([profile], password: password, to: destination) { _ in
                throw ShuttleError.credentials("Keychain access was cancelled.")
            }
        }
        let credentialMarker = "DO-NOT-DISCLOSE-SAVED-PASSWORD"
        do {
            try EncryptedBackup.exportProfiles([profile], password: password, to: destination) { _ in
                throw NSError(domain: "SyntheticCredentialProvider", code: 1,
                              userInfo: [NSLocalizedDescriptionKey: credentialMarker])
            }
            Issue.record("A failed credential capture was accepted.")
        } catch {
            #expect(error is ShuttleError)
            #expect(!error.localizedDescription.contains(credentialMarker))
        }
        #expect(try Data(contentsOf: destination) == original)
        for path in ["relative-key", root.appendingPathComponent("missing").path] {
            var invalid = profile
            invalid.identityFile = path
            #expect(throws: ShuttleError.self) {
                try EncryptedBackup.exportProfiles([invalid], password: password, to: destination) { _ in "saved" }
            }
        }
        for invalidPassword in ["short", String(repeating: "x", count: 1025)] {
            #expect(throws: ShuttleError.self) {
                try EncryptedBackup.exportProfiles([profile], password: invalidPassword, to: destination) { _ in "saved" }
            }
        }
        #expect(try Data(contentsOf: destination) == original)
        #expect(try Data(contentsOf: key) == firstKey)
        #expect(try FileManager.default.contentsOfDirectory(atPath: root.path).count == 2)
    }

    @Test func referencedSourceFilesAndHardLinksCannotBeExportDestinations() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let key = root.appendingPathComponent("key")
        let config = root.appendingPathComponent("config")
        try firstKey.write(to: key)
        let configData = Data("Host alias\n".utf8)
        try configData.write(to: config)
        let alias = root.appendingPathComponent("key-hard-link")
        try #require(link(key.path, alias.path) == 0)
        let profile = ServerProfile(name: "Saved", host: "saved.test", identity: .privateKey,
                                    identityFile: key.path, sshConfigPath: config.path)
        for destination in [key, config, alias] {
            #expect(throws: ShuttleError.self) {
                try EncryptedBackup.exportProfiles([profile], password: password, to: destination) { _ in nil }
            }
        }
        var padded = profile
        padded.identityFile = " \t" + key.path + " \n"
        for destination in [key, alias] {
            #expect(throws: ShuttleError.self) {
                try EncryptedBackup.exportProfiles([padded], password: password, to: destination) { _ in nil }
            }
        }
        #expect(try Data(contentsOf: key) == firstKey)
        #expect(try Data(contentsOf: alias) == firstKey)
        #expect(try Data(contentsOf: config) == configData)
    }

    @Test func rejectsSymlinksAndSpecialFilesWithoutBlockingOrChangingTargets() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let target = root.appendingPathComponent("key")
        try firstKey.write(to: target)
        let symlink = root.appendingPathComponent("link")
        try FileManager.default.createSymbolicLink(at: symlink, withDestinationURL: target)
        let fifo = root.appendingPathComponent("pipe")
        try #require(mkfifo(fifo.path, mode_t(0o600)) == 0)
        let backup = root.appendingPathComponent("backup")
        for input in [symlink, fifo, root] {
            #expect(throws: ShuttleError.self) { try EncryptedBackup.isBackup(at: input) }
            #expect(throws: ShuttleError.self) { try EncryptedBackup.importProfiles(from: input, password: password) }
            let profile = ServerProfile(name: "Key", host: "key.test", identity: .privateKey, identityFile: input.path)
            #expect(throws: ShuttleError.self) {
                try EncryptedBackup.exportProfiles([profile], password: password, to: backup) { _ in nil }
            }
            #expect(throws: ShuttleError.self) {
                try EncryptedBackup.exportProfiles([], password: password, to: input) { _ in nil }
            }
        }
        #expect(!FileManager.default.fileExists(atPath: backup.path))
        #expect(try Data(contentsOf: target) == firstKey)
    }

    @Test func enforcesFileKeyEntryAndCumulativeBoundsBeforeReplacingDestination() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let oversizedFile = root.appendingPathComponent("oversized")
        let descriptor = open(oversizedFile.path, O_WRONLY | O_CREAT | O_EXCL, mode_t(0o600))
        try #require(descriptor >= 0)
        try #require(ftruncate(descriptor, off_t(64 * 1024 * 1024 + 1)) == 0)
        close(descriptor)
        #expect(throws: ShuttleError.self) { try EncryptedBackup.isBackup(at: oversizedFile) }
        #expect(throws: ShuttleError.self) { try EncryptedBackup.importProfiles(from: oversizedFile, password: password) }
        let ordinary = root.appendingPathComponent("ordinary")
        try Data("not a backup".utf8).write(to: ordinary)
        #expect(try !EncryptedBackup.isBackup(at: ordinary))
        let key = root.appendingPathComponent("large-key")
        let framing = "-----BEGIN PRIVATE KEY-----\n\n-----END PRIVATE KEY-----\n"
        let bodySize = ((1024 * 1024 - framing.utf8.count) / 4) * 4
        let validLargeKey = Data(("-----BEGIN PRIVATE KEY-----\n" + String(repeating: "A", count: bodySize)
                                 + "\n-----END PRIVATE KEY-----\n").utf8)
        try validLargeKey.write(to: key)
        let destination = root.appendingPathComponent("destination")
        let original = Data("keep destination".utf8)
        try original.write(to: destination)
        let profiles = (0..<34).map {
            ServerProfile(name: "Key \($0)", host: "key-\($0).test", identity: .privateKey, identityFile: key.path)
        }
        let tooMany = (0...10_000).map { ServerProfile(name: "Host \($0)", host: "host.test") }
        for invalid in [profiles, tooMany, [profiles[0], profiles[0]]] {
            #expect(throws: ShuttleError.self) {
                try EncryptedBackup.exportProfiles(invalid, password: password, to: destination) { _ in nil }
            }
        }
        try Data(repeating: 0x41, count: 1024 * 1024 + 1).write(to: key)
        #expect(throws: ShuttleError.self) {
            try EncryptedBackup.exportProfiles([profiles[0]], password: password, to: destination) { _ in nil }
        }
        #expect(try Data(contentsOf: destination) == original)
    }

    @Test func authenticatedButInvalidPayloadsFailBeforeReturningAnyCandidates() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let backup = root.appendingPathComponent("valid")
        let malformed = root.appendingPathComponent("malformed")
        let profile = ServerProfile(name: "Saved", host: "saved.test", passwordMode: .keychain)
        try EncryptedBackup.exportProfiles([profile], password: password, to: backup) { _ in "saved-secret" }
        let encrypted = try Data(contentsOf: backup)
        let (header, key, payload) = try independentlyOpen(encrypted)
        let document = try #require(JSONSerialization.jsonObject(with: payload) as? [String: Any])
        let entries = try #require(document["entries"] as? [[String: Any]])
        let first = try #require(entries.first)
        var noPassword = first
        noPassword.removeValue(forKey: "password")
        var unsolicitedKey = first
        unsolicitedKey["privateKey"] = firstKey.base64EncodedString()
        var invalidProfile = first
        var fields = try #require(first["profile"] as? [String: Any])
        fields["host"] = "-bad-host"
        invalidProfile["profile"] = fields
        var keyFields = try #require(first["profile"] as? [String: Any])
        keyFields["identity"] = "privateKey"
        keyFields["identityFile"] = "/source/key"
        var missingKey = first
        missingKey["profile"] = keyFields
        var invalidKey = missingKey
        invalidKey["privateKey"] = Data("not a complete private key".utf8).base64EncodedString()
        var unexpectedPassword = first
        var passwordFields = try #require(first["profile"] as? [String: Any])
        passwordFields["passwordMode"] = "askWhenNeeded"
        unexpectedPassword["profile"] = passwordFields
        let badPayloads: [[String: Any]] = [
            ["version": 2, "entries": entries],
            ["version": 1, "entries": [first, first]],
            ["version": 1, "entries": Array(repeating: first, count: 10_001)],
            ["version": 1, "entries": [noPassword]],
            ["version": 1, "entries": [unsolicitedKey]],
            ["version": 1, "entries": [invalidProfile]],
            ["version": 1, "entries": [missingKey]],
            ["version": 1, "entries": [invalidKey]],
            ["version": 1, "entries": [unexpectedPassword]]
        ]
        for invalid in badPayloads {
            let plaintext = try JSONSerialization.data(withJSONObject: invalid)
            let sealed = try AES.GCM.seal(plaintext, using: key, authenticating: header)
            var bytes = header
            bytes.append(try #require(sealed.combined))
            try bytes.write(to: malformed)
            #expect(throws: ShuttleError.self) { try EncryptedBackup.importProfiles(from: malformed, password: password) }
        }
        #expect(try Data(contentsOf: backup) == encrypted)
        #expect(try FileManager.default.contentsOfDirectory(atPath: root.path).count == 2)
    }

    /// Independent native decoding verifies the public on-disk format, not private implementation wiring.
    private func independentlyOpen(_ encrypted: Data) throws -> (Data, SymmetricKey, Data) {
        let magic = Data("ShuttleNextBackup\0".utf8)
        try #require(encrypted.prefix(magic.count) == magic)
        try #require(encrypted[magic.count] == 1)
        let headerSize = magic.count + 1 + 32
        let header = Data(encrypted.prefix(headerSize))
        let salt = Data(header.suffix(32))
        let passwordBytes = Array(password.utf8)
        var derived = Data(count: 32)
        let status = derived.withUnsafeMutableBytes { output in
            salt.withUnsafeBytes { saltBuffer in
                passwordBytes.withUnsafeBytes { input in
                    CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), input.baseAddress!.assumingMemoryBound(to: CChar.self), input.count,
                                        saltBuffer.baseAddress!.assumingMemoryBound(to: UInt8.self), saltBuffer.count,
                                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), 600_000,
                                        output.baseAddress!.assumingMemoryBound(to: UInt8.self), output.count)
                }
            }
        }
        try #require(status == kCCSuccess)
        let key = SymmetricKey(data: derived)
        let box = try AES.GCM.SealedBox(combined: encrypted.suffix(from: headerSize))
        return (header, key, try AES.GCM.open(box, using: key, authenticating: header))
    }
}
