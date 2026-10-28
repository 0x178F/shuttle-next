import Foundation
import Testing
import ShuttleCore
@testable import ShuttleNext

/// Isolates the Keychain boundary while all library, archive, and key files remain real.
private final class BackupCredentials: ServerCredentials, @unchecked Sendable {
    enum Failure: Error, Equatable { case denied, writeFailed, cleanupFailed }
    private let lock = NSLock()
    private var passwords: [UUID: String]
    private var writeCount = 0
    private var waited = false
    private var observedMainThreadRead = false
    private var observedRead = false
    private let deniedReads: Set<UUID>
    private let failWrite: Int?
    private let failDelete: Bool
    private let readGate: CredentialBoundaryGate?
    private let writeGate: CredentialBoundaryGate?

    init(_ passwords: [UUID: String] = [:], deniedReads: Set<UUID> = [], failWrite: Int? = nil,
         failDelete: Bool = false, readGate: CredentialBoundaryGate? = nil, writeGate: CredentialBoundaryGate? = nil) {
        self.passwords = passwords
        self.deniedReads = deniedReads
        self.failWrite = failWrite
        self.failDelete = failDelete
        self.readGate = readGate
        self.writeGate = writeGate
    }

    var snapshot: [UUID: String] { lock.withLock { passwords } }
    var readOnMainThread: Bool { lock.withLock { observedMainThreadRead } }
    var didReadPassword: Bool { lock.withLock { observedRead } }

    private func waitOnce(_ gate: CredentialBoundaryGate?) {
        guard let gate else { return }
        let shouldWait = lock.withLock {
            if waited { return false }
            waited = true
            return true
        }
        if shouldWait {
            gate.enterAndWait()
        }
    }

    func password(for id: UUID) throws -> String? {
        lock.withLock {
            observedRead = true
            observedMainThreadRead = observedMainThreadRead || Thread.isMainThread
        }
        waitOnce(readGate)
        if deniedReads.contains(id) { throw Failure.denied }
        return lock.withLock { passwords[id] }
    }

    func containsPassword(for id: UUID) throws -> Bool { lock.withLock { passwords[id] != nil } }

    func setPassword(_ password: String, for id: UUID) throws {
        let count = lock.withLock {
            passwords[id] = password
            writeCount += 1
            return writeCount
        }
        waitOnce(writeGate)
        // A failed credential call is allowed to have mutated state first.
        if count == failWrite { throw Failure.writeFailed }
    }

    func deletePassword(for id: UUID) throws {
        if failDelete { throw Failure.cleanupFailed }
        lock.withLock { passwords[id] = nil }
    }
}

@MainActor
struct BackupRestoreTests {
    private let backupPassword = "portable backup password"
    private let firstKey = Data("-----BEGIN OPENSSH PRIVATE KEY-----\nYWJj\n-----END OPENSSH PRIVATE KEY-----\n".utf8)
    private let secondKey = Data("-----BEGIN ENCRYPTED PRIVATE KEY-----\nZGVm\n-----END ENCRYPTED PRIVATE KEY-----\n".utf8)

    private func directory() throws -> URL {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("ShuttleNext-backup-runtime-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        return root
    }

    private func keyFiles(in root: URL) throws -> [URL] {
        let directory = root.appendingPathComponent("keys", isDirectory: true)
        guard FileManager.default.fileExists(atPath: directory.path) else { return [] }
        return try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
    }

    @discardableResult
    private func expectFailure(_ operation: @MainActor () async throws -> Void) async -> Error? {
        do {
            try await operation()
            Issue.record("An operation expected to fail unexpectedly succeeded")
            return nil
        } catch { return error }
    }

    @Test func encryptedRoundTripKeepsEachServersOwnSecretsOnANewMac() async throws {
        let root = try directory()
        defer { try? FileManager.default.removeItem(at: root) }
        let source = ProfileRepository(directory: root.appendingPathComponent("source"))
        let sourceKeys = PrivateKeyFileStore(directory: source.directory.appendingPathComponent("keys"))
        let firstURL = try sourceKeys.create(from: String(decoding: firstKey, as: UTF8.self))
        let secondURL = try sourceKeys.create(from: String(decoding: secondKey, as: UTF8.self))
        let first = ServerProfile(name: "First", host: "192.0.2.1", identity: .privateKey,
                                  passwordMode: .keychain, identityFile: firstURL.path)
        let second = ServerProfile(name: "Second", host: "192.0.2.2", identity: .privateKey,
                                   passwordMode: .keychain, identityFile: secondURL.path)
        let automatic = ServerProfile(name: "Automatic", host: "192.0.2.3")
        try source.save(LibraryDocument(profiles: [first, second, automatic]))
        let sourceCredentials = BackupCredentials([first.id: "first server password", second.id: "second server password"])
        let exporting = AppModel(repository: source, credentials: sourceCredentials)
        let archive = root.appendingPathComponent("portable.shuttlenext")
        try await exporting.exportConnections(to: archive, backupPassword: backupPassword)
        #expect(!sourceCredentials.readOnMainThread)

        let destination = ProfileRepository(directory: root.appendingPathComponent("destination"))
        let destinationCredentials = BackupCredentials()
        let restoring = AppModel(repository: destination, credentials: destinationCredentials)
        await expectFailure { _ = try await restoring.unlockBackup(from: archive, password: "incorrect password") }
        #expect(restoring.profiles.isEmpty)
        #expect(destinationCredentials.snapshot.isEmpty)
        #expect(try keyFiles(in: destination.directory).isEmpty)
        let preview = try await restoring.unlockBackup(from: archive, password: backupPassword)
        #expect(preview.isEncryptedBackup)
        #expect(restoring.profiles.isEmpty)
        #expect(destinationCredentials.snapshot.isEmpty)
        try await restoring.importCandidates(preview.candidates, allowDuplicates: true)

        let restored = try destination.load()
        #expect(restored.profiles.count == 3)
        for (name, key, password) in [("First", firstKey, "first server password"), ("Second", secondKey, "second server password")] {
            let profile = try #require(restored.profiles.first { $0.name == name })
            #expect(profile.id != first.id && profile.id != second.id)
            #expect(destinationCredentials.snapshot[profile.id] == password)
            #expect(profile.passwordMode == .keychain)
            #expect(profile.identity == .privateKey)
            let keyURL = URL(fileURLWithPath: profile.identityFile)
            #expect(keyURL.deletingLastPathComponent().path == destination.directory.appendingPathComponent("keys").path)
            #expect(try Data(contentsOf: keyURL) == key)
            let attributes = try FileManager.default.attributesOfItem(atPath: keyURL.path)
            #expect((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o600)
        }
        let restoredAutomatic = try #require(restored.profiles.first { $0.name == "Automatic" })
        #expect(restoredAutomatic.identity == .automatic)
        #expect(destinationCredentials.snapshot.count == 2)
        #expect(try Data(contentsOf: firstURL) == firstKey)
        #expect(try Data(contentsOf: secondURL) == secondKey)
        #expect(!restoring.isLibraryBusy)
    }

    @Test func explicitBackupCopiesUseSeparateRecordsAndNeverClaimExistingCredentials() async throws {
        let root = try directory()
        defer { try? FileManager.default.removeItem(at: root) }
        let repository = ProfileRepository(directory: root)
        let existing = ServerProfile(name: "Existing", host: "EXAMPLE.com", user: "alice", port: 22, passwordMode: .keychain)
        try repository.save(LibraryDocument(profiles: [existing]))
        let orphanID = UUID()
        let credentials = BackupCredentials([existing.id: "original password", orphanID: "unrelated orphan"])
        let model = AppModel(repository: repository, credentials: credentials)
        var candidate = existing
        candidate.id = UUID()
        candidate.host = "example.COM"
        #expect(model.isDuplicate(candidate))
        #expect(model.isBackupConflict(candidate))
        try await model.importCandidates([ImportCandidate(profile: candidate, password: "copy password")])
        #expect(model.profiles == [existing])
        try await model.importCandidates([ImportCandidate(profile: existing, password: "copy password")], allowDuplicates: true)
        let copy = try #require(model.profiles.last)
        #expect(copy.id != existing.id)
        #expect(credentials.snapshot[copy.id] == "copy password")
        #expect(credentials.snapshot[existing.id] == "original password")

        var orphanCandidate = ServerProfile(id: orphanID, name: "Unrelated", host: "192.0.2.8", passwordMode: .keychain)
        try await model.importCandidates([ImportCandidate(profile: orphanCandidate, password: "new password")], allowDuplicates: true)
        #expect(model.profiles.last?.id != orphanID)
        #expect(credentials.snapshot[orphanID] == "unrelated orphan")
        orphanCandidate.identity = .privateKey
        orphanCandidate.identityFile = "/different/selected/key"
        orphanCandidate.host = existing.host
        orphanCandidate.user = existing.user
        orphanCandidate.port = existing.port
        #expect(model.isBackupConflict(orphanCandidate))
        #expect(!model.isDuplicate(orphanCandidate))
        orphanCandidate.port = nil
        #expect(!model.isBackupConflict(orphanCandidate))
    }

    @Test func unresolvedConfigurationBlocksWritesUntilExplicitlyResolved() async throws {
        let root = try directory()
        defer { try? FileManager.default.removeItem(at: root) }
        let repository = ProfileRepository(directory: root)
        let original = LibraryDocument(settings: AppSettings(language: .de))
        try repository.save(original)
        let credentials = BackupCredentials()
        let model = AppModel(repository: repository, credentials: credentials)
        let profile = ServerProfile(name: "Requires config", host: "192.0.2.1", identity: .privateKey,
                                    passwordMode: .keychain, identityFile: "/source/key", sshConfigPath: "/source/config")
        let unresolved = ImportCandidate(profile: profile, password: "server password", privateKey: firstKey, requiresSSHConfiguration: true)
        await expectFailure { try await model.importCandidates([unresolved], allowDuplicates: true) }
        #expect(try repository.load() == original)
        #expect(model.document == original)
        #expect(credentials.snapshot.isEmpty)
        #expect(try keyFiles(in: root).isEmpty)
        #expect(!model.isLibraryBusy)

        let config = root.appendingPathComponent("trusted_config")
        try Data("Host test\n    HostName 192.0.2.1\n".utf8).write(to: config)
        var resolved = unresolved
        resolved.requiresSSHConfiguration = false
        resolved.profile.sshConfigPath = config.path
        try await model.importCandidates([resolved], allowDuplicates: true)
        #expect(model.profiles.first?.sshConfigPath == config.path)
        #expect(model.settings == original.settings)
        #expect(try keyFiles(in: root).count == 1)
    }

    @Test func duplicateCandidateIdentifiersAreRejectedEvenForExplicitCopies() async throws {
        let root = try directory()
        defer { try? FileManager.default.removeItem(at: root) }
        let repository = ProfileRepository(directory: root)
        let credentials = BackupCredentials()
        let model = AppModel(repository: repository, credentials: credentials)
        let profile = ServerProfile(name: "Duplicate", host: "192.0.2.1", passwordMode: .keychain)
        let candidate = ImportCandidate(profile: profile, password: "server password")
        await expectFailure { try await model.importCandidates([candidate, candidate], allowDuplicates: true) }
        #expect(try repository.load().profiles.isEmpty)
        #expect(credentials.snapshot.isEmpty)
    }

    @Test func credentialFailureRollsBackBothServersAndOnlyNewKeyFiles() async throws {
        let root = try directory()
        defer { try? FileManager.default.removeItem(at: root) }
        let repository = ProfileRepository(directory: root)
        let keyStore = PrivateKeyFileStore(directory: root.appendingPathComponent("keys"))
        let existingKey = try keyStore.create(from: String(decoding: firstKey, as: UTF8.self))
        let existing = ServerProfile(name: "Existing", host: "192.0.2.9", identity: .privateKey,
                                     passwordMode: .keychain, identityFile: existingKey.path)
        let original = LibraryDocument(profiles: [existing], settings: AppSettings(language: .tr))
        try repository.save(original)
        let originalBytes = try Data(contentsOf: repository.fileURL)
        let credentials = BackupCredentials([existing.id: "existing password"], failWrite: 2)
        let model = AppModel(repository: repository, credentials: credentials)
        let first = ServerProfile(name: "First", host: "192.0.2.1", identity: .privateKey,
                                  passwordMode: .keychain, identityFile: "/old/first")
        let second = ServerProfile(name: "Second", host: "192.0.2.2", identity: .privateKey,
                                   passwordMode: .keychain, identityFile: "/old/second")
        let error = await expectFailure {
            try await model.importCandidates([
                ImportCandidate(profile: first, password: "first password", privateKey: firstKey),
                ImportCandidate(profile: second, password: "second password", privateKey: secondKey)
            ], allowDuplicates: true)
        }
        #expect(error as? BackupCredentials.Failure == .writeFailed)
        #expect(try Data(contentsOf: repository.fileURL) == originalBytes)
        #expect(try repository.load() == original)
        #expect(model.document == original)
        #expect(credentials.snapshot == [existing.id: "existing password"])
        let remainingKeys = try keyFiles(in: root)
        #expect(remainingKeys.map { $0.standardizedFileURL.resolvingSymlinksInPath().path } ==
                [existingKey.standardizedFileURL.resolvingSymlinksInPath().path])
        #expect(try Data(contentsOf: existingKey) == firstKey)
        #expect(!model.isLibraryBusy)
    }

    @Test func malformedLaterKeyRollsBackEarlierKeyAndPassword() async throws {
        let root = try directory()
        defer { try? FileManager.default.removeItem(at: root) }
        let repository = ProfileRepository(directory: root)
        let credentials = BackupCredentials()
        let model = AppModel(repository: repository, credentials: credentials)
        let first = ServerProfile(name: "First", host: "192.0.2.1", identity: .privateKey,
                                  passwordMode: .keychain, identityFile: "/old/first")
        let second = ServerProfile(name: "Second", host: "192.0.2.2", identity: .privateKey, identityFile: "/old/second")
        await expectFailure {
            try await model.importCandidates([
                ImportCandidate(profile: first, password: "first password", privateKey: firstKey),
                ImportCandidate(profile: second, privateKey: Data("not a private key".utf8))
            ], allowDuplicates: true)
        }
        #expect(try repository.load().profiles.isEmpty)
        #expect(credentials.snapshot.isEmpty)
        #expect(try keyFiles(in: root).isEmpty)
    }

    @Test func rollbackFailureIsReportedInsteadOfSilentlyHidingAnOrphanCredential() async throws {
        let root = try directory()
        defer { try? FileManager.default.removeItem(at: root) }
        let repository = ProfileRepository(directory: root)
        let credentials = BackupCredentials(failWrite: 1, failDelete: true)
        let model = AppModel(repository: repository, credentials: credentials)
        let profile = ServerProfile(name: "First", host: "192.0.2.1", passwordMode: .keychain)
        let error = await expectFailure { try await model.importCandidates([ImportCandidate(profile: profile, password: "password")]) }
        #expect(try repository.load().profiles.isEmpty)
        #expect(credentials.snapshot[profile.id] == "password")
        let rollbackError = try #require(error as? ShuttleError)
        if case .storage = rollbackError {
            // Incomplete rollback must be surfaced, not the original write-boundary failure.
        } else {
            Issue.record("A credential rollback failure was not reported as a storage recovery error")
        }
        #expect(!model.isLibraryBusy)
    }

    @Test(arguments: [false, true])
    func exportCannotReplaceLibraryOrReferencedFiles(encrypted: Bool) async throws {
        let root = try directory()
        defer { try? FileManager.default.removeItem(at: root) }
        let repository = ProfileRepository(directory: root)
        let key = root.appendingPathComponent("selected_key")
        let config = root.appendingPathComponent("selected_config")
        try firstKey.write(to: key)
        try Data("Host example\n".utf8).write(to: config)
        let profile = ServerProfile(name: "Protected", host: "192.0.2.1", identity: .privateKey,
                                    identityFile: key.path, sshConfigPath: config.path)
        try repository.save(LibraryDocument(profiles: [profile]))
        let hardLink = root.appendingPathComponent("library-hardlink")
        try FileManager.default.linkItem(at: repository.fileURL, to: hardLink)
        let directoryAlias = root.appendingPathComponent("folder-alias")
        try FileManager.default.createSymbolicLink(at: directoryAlias, withDestinationURL: root)
        let model = AppModel(repository: repository, credentials: BackupCredentials())
        for target in [repository.fileURL, key, config, hardLink, directoryAlias.appendingPathComponent("selected_key")] {
            let before = try Data(contentsOf: target)
            await expectFailure { try await model.exportConnections(to: target, backupPassword: encrypted ? backupPassword : nil) }
            #expect(try Data(contentsOf: target) == before)
            #expect(!model.isProcessingBackup)
        }
    }

    @Test(arguments: [false, true])
    func unavailablePasswordAbortsWithoutReplacingDestination(denied: Bool) async throws {
        let root = try directory()
        defer { try? FileManager.default.removeItem(at: root) }
        let repository = ProfileRepository(directory: root)
        let profile = ServerProfile(name: "Password", host: "192.0.2.1", passwordMode: .keychain)
        try repository.save(LibraryDocument(profiles: [profile]))
        let credentials = BackupCredentials(deniedReads: denied ? [profile.id] : [])
        let model = AppModel(repository: repository, credentials: credentials)
        let destination = root.appendingPathComponent("existing.shuttlenext")
        let original = Data("keep this destination".utf8)
        try original.write(to: destination)
        await expectFailure { try await model.exportConnections(to: destination, backupPassword: backupPassword) }
        #expect(try Data(contentsOf: destination) == original)
        #expect(model.profiles == [profile])
        #expect(credentials.snapshot.isEmpty)
        #expect(!model.isLibraryBusy)
    }

    @Test func cancelledExportRemainsResponsiveAndBlocksReentrantMutations() async throws {
        let root = try directory()
        defer { try? FileManager.default.removeItem(at: root) }
        let repository = ProfileRepository(directory: root)
        let profile = ServerProfile(name: "Password", host: "192.0.2.1", passwordMode: .keychain)
        try repository.save(LibraryDocument(profiles: [profile]))
        let gate = CredentialBoundaryGate()
        defer { gate.release() }
        let credentials = BackupCredentials([profile.id: "server password"], readGate: gate)
        let model = AppModel(repository: repository, credentials: credentials)
        let destination = root.appendingPathComponent("existing.shuttlenext")
        let original = Data("existing archive".utf8)
        try original.write(to: destination)
        let export = Task {
            defer { gate.finish() }
            try await model.exportConnections(to: destination, backupPassword: backupPassword)
        }
        let entered = await gate.waitForEntry()
        try #require(entered)
        #expect(model.isProcessingBackup && model.isLibraryBusy)
        #expect(!model.canDismissPopover)
        #expect(throws: ShuttleError.self) { try model.save(ServerProfile(name: "Reentrant", host: "192.0.2.2"), password: nil) }
        await expectFailure { try await model.importCandidates([]) }
        await expectFailure { _ = try await model.unlockBackup(from: destination, password: backupPassword) }
        export.cancel()
        gate.release()
        await expectFailure { try await export.value }
        #expect(try Data(contentsOf: destination) == original)
        #expect(try repository.load().profiles == [profile])
        #expect(!credentials.readOnMainThread)
        #expect(!model.isLibraryBusy && model.canDismissPopover)
    }

    @Test func cancelledRestoreRollsBackUncommittedKeysAndCredentials() async throws {
        let root = try directory()
        defer { try? FileManager.default.removeItem(at: root) }
        let repository = ProfileRepository(directory: root)
        let gate = CredentialBoundaryGate()
        defer { gate.release() }
        let credentials = BackupCredentials(writeGate: gate)
        let model = AppModel(repository: repository, credentials: credentials)
        let profile = ServerProfile(name: "Imported", host: "192.0.2.1", identity: .privateKey,
                                    passwordMode: .keychain, identityFile: "/source/key")
        let candidate = ImportCandidate(profile: profile, password: "server password", privateKey: firstKey)
        let restore = Task {
            defer { gate.finish() }
            try await model.importCandidates([candidate], allowDuplicates: true)
        }
        let entered = await gate.waitForEntry()
        try #require(entered)
        #expect(model.isImporting && !model.canDismissPopover)
        restore.cancel()
        gate.release()
        await expectFailure { try await restore.value }
        #expect(try repository.load().profiles.isEmpty)
        #expect(model.profiles.isEmpty)
        #expect(credentials.snapshot.isEmpty)
        #expect(try keyFiles(in: root).isEmpty)
        #expect(!model.isLibraryBusy)
    }

    @Test func repositoryCommitFailureRollsBackKeysAndCredentialsWithoutChangingLibrary() async throws {
        let root = try directory()
        defer { try? FileManager.default.removeItem(at: root) }
        let repository = ProfileRepository(directory: root)
        let original = LibraryDocument(settings: AppSettings(language: .fr))
        try repository.save(original)
        let originalBytes = try Data(contentsOf: repository.fileURL)
        let gate = CredentialBoundaryGate()
        defer { gate.release() }
        let credentials = BackupCredentials(writeGate: gate)
        let model = AppModel(repository: repository, credentials: credentials)
        let profile = ServerProfile(name: "Imported", host: "192.0.2.1", identity: .privateKey,
                                    passwordMode: .keychain, identityFile: "/source/key")
        let candidate = ImportCandidate(profile: profile, password: "server password", privateKey: firstKey)
        let restore = Task {
            defer { gate.finish() }
            try await model.importCandidates([candidate], allowDuplicates: true)
        }
        let entered = await gate.waitForEntry()
        try #require(entered)
        // Fail the real repository's next lock acquisition, without changing library bytes.
        let lock = root.appendingPathComponent(".library.lock")
        do {
            try FileManager.default.removeItem(at: lock)
            try FileManager.default.createSymbolicLink(at: lock, withDestinationURL: repository.fileURL)
        } catch {
            gate.release()
            _ = await restore.result
            throw error
        }
        gate.release()
        await expectFailure { try await restore.value }
        #expect(try Data(contentsOf: repository.fileURL) == originalBytes)
        #expect(model.document == original)
        #expect(credentials.snapshot.isEmpty)
        #expect(try keyFiles(in: root).isEmpty)
        #expect(!model.isLibraryBusy)
    }

    @Test func exportsReadFreshLibraryAndMetadataExportNeverReadsCredentials() async throws {
        let root = try directory()
        defer { try? FileManager.default.removeItem(at: root) }
        let repository = ProfileRepository(directory: root)
        let stale = ServerProfile(name: "Stale", host: "192.0.2.1")
        try repository.save(LibraryDocument(profiles: [stale]))
        let fresh = ServerProfile(name: "Fresh", host: "192.0.2.2", passwordMode: .keychain)
        let credentials = BackupCredentials([fresh.id: "fresh server password"], deniedReads: [stale.id])
        let model = AppModel(repository: repository, credentials: credentials)
        try repository.save(LibraryDocument(profiles: [fresh]))
        let backup = root.appendingPathComponent("fresh.shuttlenext")
        try await model.exportConnections(to: backup, backupPassword: backupPassword)
        let restored = try await model.unlockBackup(from: backup, password: backupPassword)
        #expect(restored.candidates.count == 1)
        #expect(restored.candidates.first?.profile.name == fresh.name)
        #expect(restored.candidates.first?.password == "fresh server password")

        let deniedCredentials = BackupCredentials([fresh.id: "fresh server password"], deniedReads: [fresh.id])
        let jsonModel = AppModel(repository: repository, credentials: deniedCredentials)
        let json = root.appendingPathComponent("connections.json")
        try await jsonModel.exportConnections(to: json, backupPassword: nil)
        let decoded = try JSONDecoder().decode(LibraryDocument.self, from: Data(contentsOf: json))
        #expect(decoded.profiles == [fresh])
        #expect(!deniedCredentials.didReadPassword)
        #expect(!String(decoding: try Data(contentsOf: json), as: UTF8.self).contains("fresh server password"))
    }
}
