import Testing
import Foundation
import Darwin
import ShuttleCore

struct PrivateKeyFileStoreTests {
    private let envelope = "-----BEGIN PRIVATE KEY-----\nAQID\n-----END PRIVATE KEY-----\n"

    private func temporaryDirectory() throws -> URL {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("ShuttleNextPrivateKeyTests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return directory
    }

    private func keygen(_ arguments: [String]) throws -> Data {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
        process.arguments = arguments
        let output = Pipe()
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        try process.run()
        process.waitUntilExit()
        try #require(process.terminationReason == .exit && process.terminationStatus == 0)
        return output.fileHandleForReading.readDataToEndOfFile()
    }

    @Test(arguments: ["\r\n", "\r"])
    func normalizesRealKeyAndKeepsItUsable(lineEnding: String) throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let source = root.appendingPathComponent("original")
        _ = try keygen(["-q", "-t", "ed25519", "-N", "", "-C", "", "-f", source.path])
        let original = try String(contentsOf: source, encoding: .utf8)
        let pasted = String(original.dropLast()).replacingOccurrences(of: "\n", with: lineEnding)
        let store = PrivateKeyFileStore(directory: root.appendingPathComponent("Library/keys"))
        let saved = try store.create(from: pasted)
        let stored = try String(contentsOf: saved, encoding: .utf8)
        #expect(stored == original)
        let originalPublicKey = try keygen(["-y", "-P", "", "-f", source.path])
        let storedPublicKey = try keygen(["-y", "-P", "", "-f", saved.path])
        #expect(storedPublicKey == originalPublicKey)
    }

    @Test func encryptedRealKeySavesWithoutPassphrase() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let source = root.appendingPathComponent("encrypted-original")
        let passphrase = "temporary-test-passphrase"
        _ = try keygen(["-q", "-t", "ed25519", "-N", passphrase, "-C", "", "-f", source.path])
        let original = try String(contentsOf: source, encoding: .utf8)
        let store = PrivateKeyFileStore(directory: root.appendingPathComponent("keys"))
        let saved = try store.create(from: original)
        #expect(try Data(contentsOf: saved) == Data(contentsOf: source))
        let originalPublicKey = try keygen(["-y", "-P", passphrase, "-f", source.path])
        let storedPublicKey = try keygen(["-y", "-P", passphrase, "-f", saved.path])
        #expect(storedPublicKey == originalPublicKey)
    }

    @Test(arguments: ["rsa", "ecdsa"])
    func encryptedPEMRemainsUsableWithoutDecryptingOnSave(algorithm: String) throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let source = root.appendingPathComponent("encrypted-pem")
        let passphrase = "temporary-pem-passphrase"
        _ = try keygen(["-q", "-t", algorithm, "-m", "PEM", "-N", passphrase, "-C", "", "-f", source.path])
        let original = try String(contentsOf: source, encoding: .utf8)
        let store = PrivateKeyFileStore(directory: root.appendingPathComponent("keys"))
        let saved = try store.create(from: original)
        #expect(try Data(contentsOf: saved) == Data(contentsOf: source))
        let originalPublicKey = try keygen(["-y", "-P", passphrase, "-f", source.path])
        let storedPublicKey = try keygen(["-y", "-P", passphrase, "-f", saved.path])
        #expect(storedPublicKey == originalPublicKey)
    }

    @Test func createsDistinctPrivateFilesWithoutReplacingExistingFiles() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let directory = root.appendingPathComponent("keys")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o777], ofItemAtPath: directory.path)
        let existing = directory.appendingPathComponent(UUID().uuidString + ".key")
        let existingData = Data("committed key remains untouched".utf8)
        try existingData.write(to: existing)
        let store = PrivateKeyFileStore(directory: directory)
        let first = try store.create(from: envelope)
        let second = try store.create(from: envelope)
        #expect(first != second)
        #expect(first.deletingLastPathComponent().path == directory.path)
        #expect(try Data(contentsOf: existing) == existingData)
        let directoryAttributes = try FileManager.default.attributesOfItem(atPath: directory.path)
        #expect((directoryAttributes[.posixPermissions] as? NSNumber)?.intValue == 0o700)
        for file in [first, second] {
            let attributes = try FileManager.default.attributesOfItem(atPath: file.path)
            #expect((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o600)
            #expect(attributes[.type] as? FileAttributeType == .typeRegular)
        }
    }

    @Test func rejectsMalformedAndPublicKeysWithSecretFreeErrors() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let directory = root.appendingPathComponent("keys")
        let store = PrivateKeyFileStore(directory: directory)
        let marker = "DO-NOT-DISCLOSE-PRIVATE-CONTENT"
        let invalid = [
            "", marker, "ssh-ed25519 AAAA \(marker)",
            "-----BEGIN PUBLIC KEY-----\nAQID\n-----END PUBLIC KEY-----",
            "-----BEGIN PRIVATE KEY-----\nAQID",
            "-----BEGIN PRIVATE KEY-----\nAQID\n-----END RSA PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY-----\n\n-----END PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY-----\n\(marker)\n-----END PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY-----\nAQID\u{0}\n-----END PRIVATE KEY-----",
            "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nAQID\n-----END RSA PRIVATE KEY-----",
            envelope + envelope,
            envelope + marker
        ]
        for text in invalid {
            do {
                _ = try store.create(from: text)
                Issue.record("Invalid private-key input was accepted.")
            } catch let error as ShuttleError {
                #expect(!error.localizedDescription.contains(marker))
                #expect(!error.localizedDescription.contains("AQID"))
                #expect(!error.localizedDescription.contains("BEGIN PRIVATE KEY"))
            }
        }
        #expect(!FileManager.default.fileExists(atPath: directory.path))
    }

    @Test func enforcesOneMiBInputBoundaryBeforeCreatingFiles() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let directory = root.appendingPathComponent("keys")
        let store = PrivateKeyFileStore(directory: directory)
        let limit = 1_048_576
        let framing = "-----BEGIN PRIVATE KEY-----\n\n-----END PRIVATE KEY-----\n"
        let payloadSize = ((limit - framing.utf8.count) / 4) * 4
        let paddingSize = limit - framing.utf8.count - payloadSize
        let exact = "-----BEGIN PRIVATE KEY-----\n" + String(repeating: "A", count: payloadSize)
            + "\n-----END PRIVATE KEY-----\n" + String(repeating: "\n", count: paddingSize)
        try #require(exact.utf8.count == limit)
        #expect(throws: ShuttleError.self) { try store.create(from: exact + "\n") }
        #expect(!FileManager.default.fileExists(atPath: directory.path))
        let saved = try store.create(from: exact)
        #expect(try Data(contentsOf: saved).count == limit - paddingSize)
    }

    @Test func enforcesCanonicalOutputBoundaryIncludingTheAddedFinalNewline() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let directory = root.appendingPathComponent("keys")
        let store = PrivateKeyFileStore(directory: directory)
        let limit = 1_048_576
        let framing = "-----BEGIN PRIVATE KEY-----\n\n-----END PRIVATE KEY-----\n"
        let payloadSize = ((limit - framing.utf8.count) / 4) * 4
        let interiorPadding = limit - framing.utf8.count - payloadSize
        let exact = "-----BEGIN PRIVATE KEY-----\n" + String(repeating: "A", count: payloadSize)
            + "\n" + String(repeating: "\n", count: interiorPadding) + "-----END PRIVATE KEY-----\n"
        try #require(exact.utf8.count == limit)
        let overflow = String(exact.replacingOccurrences(of: "\n-----END", with: "\n\n-----END").dropLast())
        try #require(overflow.utf8.count == limit)
        #expect(throws: ShuttleError.self) { try store.create(from: overflow) }
        #expect(!FileManager.default.fileExists(atPath: directory.path))
        let withoutFinalNewline = String(exact.dropLast())
        let saved = try store.create(from: withoutFinalNewline)
        #expect(try Data(contentsOf: saved) == Data(exact.utf8))
        let savedWithFinalNewline = try store.create(from: exact)
        #expect(try Data(contentsOf: savedWithFinalNewline) == Data(exact.utf8))
    }

    @Test func rejectsSymlinkStoreWithoutTouchingTarget() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let target = root.appendingPathComponent("target")
        try FileManager.default.createDirectory(at: target, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: target.path)
        let existing = target.appendingPathComponent(UUID().uuidString + ".key")
        let data = Data("existing file".utf8)
        try data.write(to: existing)
        let link = root.appendingPathComponent("keys")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)
        let store = PrivateKeyFileStore(directory: link)
        #expect(throws: ShuttleError.self) { try store.create(from: envelope) }
        #expect(throws: ShuttleError.self) { try store.removeCreatedFile(at: link.appendingPathComponent(existing.lastPathComponent)) }
        #expect(try Data(contentsOf: existing) == data)
        #expect(try FileManager.default.contentsOfDirectory(atPath: target.path) == [existing.lastPathComponent])
        let attributes = try FileManager.default.attributesOfItem(atPath: target.path)
        #expect((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o755)
    }

    @Test func rollbackOnlyRemovesDirectUUIDRegularFileAndPreservesOtherKeys() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let directory = root.appendingPathComponent("keys")
        let store = PrivateKeyFileStore(directory: directory)
        let rollback = try store.create(from: envelope)
        let committed = try store.create(from: envelope)
        let outside = root.appendingPathComponent(UUID().uuidString + ".key")
        let data = Data("untouched".utf8)
        try data.write(to: outside)
        let ordinary = directory.appendingPathComponent("not-a-created-key")
        try data.write(to: ordinary)
        let symlink = directory.appendingPathComponent(UUID().uuidString + ".key")
        try FileManager.default.createSymbolicLink(at: symlink, withDestinationURL: outside)
        let subdirectory = directory.appendingPathComponent(UUID().uuidString + ".key")
        try FileManager.default.createDirectory(at: subdirectory, withIntermediateDirectories: false)
        let traversal = URL(fileURLWithPath: directory.path + "/nested/../" + committed.lastPathComponent)
        let outsideTraversal = URL(fileURLWithPath: directory.path + "/../" + outside.lastPathComponent)
        for rejected in [outside, ordinary, symlink, subdirectory, traversal, outsideTraversal] {
            #expect(throws: ShuttleError.self) { try store.removeCreatedFile(at: rejected) }
        }
        try store.removeCreatedFile(at: rollback)
        #expect(!FileManager.default.fileExists(atPath: rollback.path))
        #expect(FileManager.default.fileExists(atPath: committed.path))
        #expect(FileManager.default.fileExists(atPath: subdirectory.path))
        #expect(try FileManager.default.destinationOfSymbolicLink(atPath: symlink.path) == outside.path)
        #expect(try Data(contentsOf: outside) == data)
        #expect(try Data(contentsOf: ordinary) == data)
    }
}
