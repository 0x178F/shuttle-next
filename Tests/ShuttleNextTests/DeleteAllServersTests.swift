import Foundation
import Testing
import ShuttleCore
@testable import ShuttleNext

private final class MemoryCredentials: ServerCredentials, @unchecked Sendable {
    enum Failure: Error { case denied }
    private let lock = NSLock()
    private var passwords: [UUID: String]
    private let denied: Set<UUID>
    private let gate: CredentialBoundaryGate?
    private var didWait = false

    init(_ passwords: [UUID: String], denied: Set<UUID> = [], gate: CredentialBoundaryGate? = nil) {
        self.passwords = passwords
        self.denied = denied
        self.gate = gate
    }

    var snapshot: [UUID: String] { lock.withLock { passwords } }
    func password(for id: UUID) throws -> String? { lock.withLock { passwords[id] } }
    func containsPassword(for id: UUID) throws -> Bool { lock.withLock { passwords[id] != nil } }
    func setPassword(_ password: String, for id: UUID) throws { lock.withLock { passwords[id] = password } }
    func deletePassword(for id: UUID) throws {
        let wait = lock.withLock {
            let wait = gate != nil && !didWait
            didWait = true
            return wait
        }
        if wait, let gate {
            gate.enterAndWait()
        }
        try lock.withLock {
            if denied.contains(id) { throw Failure.denied }
            passwords.removeValue(forKey: id)
        }
    }
}

@MainActor
struct DeleteAllServersTests {
    private func directory() throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("ShuttleNext-delete-all-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    @Test func deletionPreservesSettingsKeysConfigAndUnrelatedCredentials() async throws {
        let root = try directory()
        defer { try? FileManager.default.removeItem(at: root) }
        let repository = ProfileRepository(directory: root.appendingPathComponent("library"))
        let keys = repository.directory.appendingPathComponent("keys")
        try FileManager.default.createDirectory(at: keys, withIntermediateDirectories: true)
        let key = keys.appendingPathComponent("retained.key")
        let config = root.appendingPathComponent("ssh-config")
        let keyData = Data("disposable key file must remain untouched".utf8)
        let configData = Data("Host fixture\n HostName 192.0.2.10\n".utf8)
        try keyData.write(to: key)
        try configData.write(to: config)
        let profiles = [
            ServerProfile(name: "Password fixture", host: "192.0.2.10", group: "Work", passwordMode: .keychain, isFavorite: true, notes: "Remove this note"),
            ServerProfile(name: "Key fixture", host: "192.0.2.20", identity: .privateKey, identityFile: key.path, sshConfigPath: config.path)
        ]
        let settings = AppSettings(terminal: .iTerm, openMode: .tab, globalShortcutEnabled: true, language: .de)
        try repository.save(LibraryDocument(profiles: profiles, settings: settings))
        let unrelated = UUID()
        let credentials = MemoryCredentials([profiles[0].id: "first fixture", profiles[1].id: "orphan fixture", unrelated: "unrelated fixture"])
        let model = AppModel(repository: repository, credentials: credentials)

        #expect(await model.removeAllServers())

        let expected = LibraryDocument(settings: settings)
        #expect(try repository.load() == expected)
        #expect(model.document == expected)
        #expect(credentials.snapshot == [unrelated: "unrelated fixture"])
        #expect(try Data(contentsOf: key) == keyData)
        #expect(try Data(contentsOf: config) == configData)
        #expect(model.groupSuggestions.isEmpty)
        #expect(model.errorMessage == nil)
        #expect(!model.isLibraryBusy && model.canDismissPopover)
    }

    @Test(arguments: [false, true])
    func damagedLibraryNeverDeletesCredentials(onInitialLoad: Bool) async throws {
        let root = try directory()
        defer { try? FileManager.default.removeItem(at: root) }
        let repository = ProfileRepository(directory: root)
        let profile = ServerProfile(name: "Retained fixture", host: "192.0.2.10", passwordMode: .keychain)
        try repository.save(LibraryDocument(profiles: [profile]))
        let damaged = Data("invalid disposable library".utf8)
        if onInitialLoad { try damaged.write(to: repository.fileURL) }
        let credentials = MemoryCredentials([profile.id: "retained fixture"])
        let model = AppModel(repository: repository, credentials: credentials)
        if !onInitialLoad { try damaged.write(to: repository.fileURL) }
        let originalDocument = model.document
        var dismissed = false
        model.nativeInteractionEnded = { dismissed = true }

        #expect(await !model.removeAllServers())

        #expect(try Data(contentsOf: repository.fileURL) == damaged)
        #expect(model.document == originalDocument)
        #expect(credentials.snapshot == [profile.id: "retained fixture"])
        #expect(model.errorMessage != nil)
        #expect(!dismissed && !model.isLibraryBusy && model.canDismissPopover)
    }

    @Test func partialPasswordFailureStillRemovesOtherPasswordsAndReportsWarning() async throws {
        let root = try directory()
        defer { try? FileManager.default.removeItem(at: root) }
        let repository = ProfileRepository(directory: root)
        let profiles = [ServerProfile(name: "Denied fixture", host: "192.0.2.10", passwordMode: .keychain),
                        ServerProfile(name: "Allowed fixture", host: "192.0.2.20", passwordMode: .keychain)]
        try repository.save(LibraryDocument(profiles: profiles, settings: AppSettings(language: .en)))
        let unrelated = UUID()
        let credentials = MemoryCredentials([profiles[0].id: "denied fixture", profiles[1].id: "allowed fixture", unrelated: "unrelated fixture"], denied: [profiles[0].id])
        let model = AppModel(repository: repository, credentials: credentials)
        var dismissed = false
        model.nativeInteractionEnded = { dismissed = true }

        #expect(await model.removeAllServers())

        #expect(try repository.load().profiles.isEmpty)
        #expect(model.profiles.isEmpty)
        #expect(credentials.snapshot == [profiles[0].id: "denied fixture", unrelated: "unrelated fixture"])
        #expect(model.errorMessage != nil)
        #expect(!dismissed && !model.isLibraryBusy && model.canDismissPopover)
    }

    @Test func emptyLibraryDoesNotTouchUnrelatedCredentials() async throws {
        let root = try directory()
        defer { try? FileManager.default.removeItem(at: root) }
        let repository = ProfileRepository(directory: root)
        let original = LibraryDocument(settings: AppSettings(language: .fr))
        try repository.save(original)
        let unrelated = UUID()
        let credentials = MemoryCredentials([unrelated: "unrelated fixture"])
        let model = AppModel(repository: repository, credentials: credentials)

        #expect(await !model.removeAllServers())

        #expect(try repository.load() == original)
        #expect(credentials.snapshot == [unrelated: "unrelated fixture"])
        #expect(model.errorMessage == nil && !model.isLibraryBusy)
    }

    @Test func deletionBlocksConcurrentMutationsAndKeepsPopoverOpen() async throws {
        let root = try directory()
        defer { try? FileManager.default.removeItem(at: root) }
        let repository = ProfileRepository(directory: root)
        let profile = ServerProfile(name: "Blocked fixture", host: "192.0.2.10", passwordMode: .keychain)
        let original = LibraryDocument(profiles: [profile], settings: AppSettings(language: .en))
        try repository.save(original)
        let gate = CredentialBoundaryGate()
        defer { gate.release() }
        let credentials = MemoryCredentials([profile.id: "fixture"], gate: gate)
        let model = AppModel(repository: repository, credentials: credentials)
        let deletion = Task {
            defer { gate.finish() }
            return await model.removeAllServers()
        }
        let entered = await gate.waitForEntry()
        try #require(entered)
        #expect(model.isDeletingServers && model.isLibraryBusy && !model.canDismissPopover)
        let anotherDeletion = await Task.detached(priority: .userInitiated) {
            await model.removeAllServers()
        }.value
        #expect(!anotherDeletion)
        var changedSettings = model.settings
        changedSettings.language = .tr
        model.updateSettings(changedSettings)
        model.toggleFavorite(profile)
        model.remove(profile)
        #expect(throws: ShuttleError.self) { try model.save(ServerProfile(name: "Must not save", host: "192.0.2.30"), password: nil) }
        model.reload()
        #expect(model.document == original)
        gate.release()

        let deleted = await deletion.value
        #expect(deleted)
        #expect(try repository.load() == LibraryDocument(settings: original.settings))
        #expect(credentials.snapshot.isEmpty)
        #expect(model.errorMessage == nil && !model.isLibraryBusy && model.canDismissPopover)
    }
}
