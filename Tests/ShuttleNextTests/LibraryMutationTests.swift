import Foundation
import Testing
import ShuttleCore
@testable import ShuttleNext

private final class TransactionCredentials: ServerCredentials, @unchecked Sendable {
    private let lock = NSLock()
    private var passwords: [UUID: String]
    private var writeHook: (@Sendable () throws -> Void)?

    init(_ passwords: [UUID: String] = [:]) { self.passwords = passwords }

    var onWrite: (@Sendable () throws -> Void)? {
        get { lock.withLock { writeHook } }
        set { lock.withLock { writeHook = newValue } }
    }
    var snapshot: [UUID: String] { lock.withLock { passwords } }
    func password(for id: UUID) throws -> String? { lock.withLock { passwords[id] } }
    func containsPassword(for id: UUID) throws -> Bool { lock.withLock { passwords[id] != nil } }
    func setPassword(_ password: String, for id: UUID) throws {
        lock.withLock { passwords[id] = password }
        try onWrite?()
    }
    func deletePassword(for id: UUID) throws { lock.withLock { passwords[id] = nil } }
}

@MainActor
struct LibraryMutationTests {
    enum Mutation: CaseIterable { case save, remove, favorite, settings, importProfiles }

    private func directory() throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("ShuttleNext-transactions-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    @Test(arguments: Mutation.allCases)
    func staleModelPreservesCommittedChanges(mutation: Mutation) async throws {
        let root = try directory()
        defer { try? FileManager.default.removeItem(at: root) }
        let repository = ProfileRepository(directory: root)
        var original = ServerProfile(name: "Original", host: "192.0.2.10")
        try repository.save(LibraryDocument(profiles: [original]))
        let model = AppModel(repository: repository, credentials: TransactionCredentials())
        original.notes = "Changed by another library writer"
        let concurrent = ServerProfile(name: "Concurrent", host: "192.0.2.20")
        let addition = ServerProfile(name: "Addition", host: "192.0.2.30")
        var expected = LibraryDocument(profiles: [original, concurrent], settings: AppSettings(language: .tr))
        try repository.save(expected)

        switch mutation {
        case .save:
            try model.save(addition, password: nil)
            expected.profiles.append(addition)
        case .remove:
            model.remove(original)
            expected.profiles.removeFirst()
        case .favorite:
            model.toggleFavorite(original)
            expected.profiles[0].isFavorite = true
        case .settings:
            var settings = model.settings
            settings.language = .de
            model.updateSettings(settings)
            expected.settings = settings
        case .importProfiles:
            try await model.importCandidates([ImportCandidate(profile: addition)])
            expected.profiles.append(addition)
        }

        #expect(try repository.load() == expected)
        #expect(model.document == expected)
        #expect(model.localizer.language == expected.settings.language)
        #expect(model.errorMessage == nil)
    }

    @Test func invalidImportPreservesPreexistingOrphanCredential() async throws {
        let root = try directory()
        defer { try? FileManager.default.removeItem(at: root) }
        let repository = ProfileRepository(directory: root)
        let original = LibraryDocument(settings: AppSettings(language: .en))
        try repository.save(original)
        let profile = ServerProfile(name: "Imported", host: "192.0.2.10", passwordMode: .keychain)
        let credentials = TransactionCredentials([profile.id: "previous orphan password"])
        let model = AppModel(repository: repository, credentials: credentials)
        let invalid = ServerProfile(name: "Invalid", host: "")

        do {
            try await model.importCandidates([ImportCandidate(profile: profile, password: "replacement"), ImportCandidate(profile: invalid)])
            Issue.record("An invalid import unexpectedly committed")
        } catch {
            #expect(error is ShuttleError)
        }

        #expect(try repository.load() == original)
        #expect(model.document == original)
        #expect(credentials.snapshot == [profile.id: "previous orphan password"])
        #expect(!model.isLibraryBusy)
    }

    @Test func importWithoutRequiredPasswordCannotCommitBrokenProfile() async throws {
        let root = try directory()
        defer { try? FileManager.default.removeItem(at: root) }
        let repository = ProfileRepository(directory: root)
        let original = LibraryDocument()
        try repository.save(original)
        let credentials = TransactionCredentials()
        let model = AppModel(repository: repository, credentials: credentials)
        let profile = ServerProfile(name: "Missing password", host: "192.0.2.10", passwordMode: .keychain)

        do {
            try await model.importCandidates([ImportCandidate(profile: profile)])
            Issue.record("An import without its required password unexpectedly committed")
        } catch {
            #expect(error is ShuttleError)
        }

        #expect(try repository.load() == original)
        #expect(credentials.snapshot.isEmpty)
    }

    @Test func reentrantCredentialPromptCannotOverwriteOrDeleteOuterSave() throws {
        let root = try directory()
        defer { try? FileManager.default.removeItem(at: root) }
        let repository = ProfileRepository(directory: root)
        let retained = ServerProfile(name: "Retained", host: "192.0.2.10")
        try repository.save(LibraryDocument(profiles: [retained], settings: AppSettings(language: .en)))
        let credentials = TransactionCredentials()
        let model = AppModel(repository: repository, credentials: credentials)
        let saved = ServerProfile(name: "Saved", host: "192.0.2.20", passwordMode: .keychain)
        var dismissed = false
        model.nativeInteractionEnded = { dismissed = true }
        credentials.onWrite = { [model] in
            MainActor.assumeIsolated {
                model.remove(retained)
                model.toggleFavorite(retained)
                var settings = model.settings
                settings.language = .tr
                model.updateSettings(settings)
                model.reload()
            }
        }
        defer { credentials.onWrite = nil }

        try model.save(saved, password: "fixture")

        let expected = LibraryDocument(profiles: [retained, saved], settings: AppSettings(language: .en))
        #expect(try repository.load() == expected)
        #expect(model.document == expected)
        #expect(credentials.snapshot == [saved.id: "fixture"])
        #expect(model.errorMessage != nil)
        #expect(!dismissed)
    }

    @Test func saveFailureRestoresPreexistingOrphanCredential() throws {
        let root = try directory()
        defer { try? FileManager.default.removeItem(at: root) }
        let repository = ProfileRepository(directory: root)
        try repository.save(LibraryDocument())
        let profile = ServerProfile(name: "Saved", host: "192.0.2.10", passwordMode: .keychain)
        let credentials = TransactionCredentials([profile.id: "previous orphan password"])
        let model = AppModel(repository: repository, credentials: credentials)
        let damaged = Data("a concurrent writer damaged this disposable library".utf8)
        credentials.onWrite = { try damaged.write(to: repository.fileURL) }

        #expect(throws: ShuttleError.self) { try model.save(profile, password: "replacement") }

        #expect(try Data(contentsOf: repository.fileURL) == damaged)
        #expect(model.profiles.isEmpty)
        #expect(credentials.snapshot == [profile.id: "previous orphan password"])
    }

    @Test(arguments: [false, true])
    func failedCredentialWriteRestoresStateAndRemovesPastedKey(updatingExisting: Bool) throws {
        enum WriteFailure: Error { case denied }
        let root = try directory()
        defer { try? FileManager.default.removeItem(at: root) }
        let repository = ProfileRepository(directory: root)
        let profile = ServerProfile(name: "Saved", host: "192.0.2.10", passwordMode: .keychain)
        let original = LibraryDocument(profiles: updatingExisting ? [profile] : [])
        try repository.save(original)
        let originalBytes = try Data(contentsOf: repository.fileURL)
        let unrelated = UUID()
        var passwords = [unrelated: "unrelated password"]
        if updatingExisting { passwords[profile.id] = "previous password" }
        let credentials = TransactionCredentials(passwords)
        let model = AppModel(repository: repository, credentials: credentials)
        credentials.onWrite = {
            credentials.onWrite = nil
            throw WriteFailure.denied
        }
        let privateKey = "-----BEGIN PRIVATE KEY-----\nAQID\n-----END PRIVATE KEY-----\n"

        #expect(throws: WriteFailure.self) {
            try model.save(profile, password: "replacement", privateKey: privateKey)
        }

        #expect(try Data(contentsOf: repository.fileURL) == originalBytes)
        #expect(try repository.load() == original)
        #expect(model.document == original)
        #expect(credentials.snapshot == passwords)
        #expect(try FileManager.default.contentsOfDirectory(atPath: root.appendingPathComponent("keys").path).isEmpty)
        #expect(!model.isLibraryBusy && model.canDismissPopover)
    }

    @Test func shortcutRollbackFailurePreservesBothErrors() throws {
        let root = try directory()
        defer { try? FileManager.default.removeItem(at: root) }
        let repository = ProfileRepository(directory: root)
        let original = LibraryDocument(settings: AppSettings(language: .en))
        try repository.save(original)
        let model = AppModel(repository: repository, credentials: TransactionCredentials())
        let damaged = Data("damaged disposable library".utf8)
        let restorationFailure = ShuttleError.connection("Fixture shortcut restoration was denied.")
        model.settingsChanged = { settings in
            if settings.globalShortcutEnabled {
                try damaged.write(to: repository.fileURL)
            } else {
                throw restorationFailure
            }
        }
        var settings = model.settings
        settings.globalShortcutEnabled = true

        model.updateSettings(settings)

        #expect(try Data(contentsOf: repository.fileURL) == damaged)
        #expect(model.document == original)
        let message = try #require(model.errorMessage)
        do {
            _ = try repository.load()
            Issue.record("The damaged library unexpectedly loaded")
        } catch {
            #expect(message.contains(model.describe(error)))
        }
        #expect(message.contains(model.describe(restorationFailure)))
    }
}
