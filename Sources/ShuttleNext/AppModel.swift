import AppKit
import Combine
import Dispatch
import Foundation
import Darwin
import ShuttleCore

protocol ServerCredentials: Sendable {
    func password(for id: UUID) throws -> String?
    func containsPassword(for id: UUID) throws -> Bool
    func setPassword(_ password: String, for id: UUID) throws
    func deletePassword(for id: UUID) throws
}

extension CredentialStore: ServerCredentials {}

@MainActor
final class AppModel: ObservableObject {
    @Published private(set) var document = LibraryDocument()
    private(set) var localizer = AppLocalizer()
    @Published var errorMessage: String?
    @Published private(set) var storageProblem: String?
    @Published private(set) var isOpeningConnection = false
    @Published private(set) var isImporting = false
    @Published private(set) var isDeletingServers = false
    @Published private(set) var isProcessingBackup = false
    @Published private(set) var availableTerminals = TerminalLauncher.availableTerminals()
    let repository: ProfileRepository
    private let credentials: any ServerCredentials
    var presentPopover: (() -> Void)?
    var settingsChanged: ((AppSettings) throws -> Void)?
    var dismissPopover: (() -> Void)?
    var nativeInteractionEnded: (() -> Void)?
    private lazy var libraryWorker = LibraryWorker()
    private var nativeInteractionDepth = 0
    private var isMutatingLibrary = false

    var isLibraryBusy: Bool { isImporting || isDeletingServers || isProcessingBackup }
    var canDismissPopover: Bool { nativeInteractionDepth == 0 && !isLibraryBusy }

    func withNativeInteraction<T>(_ operation: () throws -> T) rethrows -> T {
        nativeInteractionDepth += 1
        var succeeded = false
        defer {
            nativeInteractionDepth -= 1
            if succeeded && errorMessage == nil && canDismissPopover { nativeInteractionEnded?() }
        }
        let result = try operation()
        succeeded = true
        return result
    }

    init(repository: ProfileRepository = ProfileRepository(), credentials: (any ServerCredentials)? = nil) {
        self.repository = repository
        if let credentials {
            self.credentials = credentials
        } else {
            let helper = Bundle.main.executableURL?.deletingLastPathComponent().appendingPathComponent("ShuttleNextHelper")
            self.credentials = CredentialStore(trustedApplications: helper.map { [$0] } ?? [])
        }
        reload()
    }

    var profiles: [ServerProfile] { document.profiles }
    var settings: AppSettings { document.settings }

    func text(_ resource: LocalizedStringResource) -> String { localizer.text(resource) }
    func describe(_ error: Error) -> String { localizer.error(error) }

    func refreshAvailableTerminals() {
        let available = TerminalLauncher.availableTerminals()
        if availableTerminals != available { availableTerminals = available }
    }

    var groupSuggestions: [String] {
        var names = Set<String>()
        for profile in profiles where !profile.group.isEmpty { names.insert(profile.group) }
        return names.sorted { $0.localizedStandardCompare($1) == .orderedAscending }
    }

    func reload() {
        guard !isLibraryBusy && !isMutatingLibrary else { return }
        do {
            let loaded = try repository.load()
            localizer = AppLocalizer(language: loaded.settings.language)
            document = loaded
            if storageProblem != nil { errorMessage = nil }
            storageProblem = nil
        } catch {
            storageProblem = describe(error)
            errorMessage = text("Your library could not be opened. It has not been replaced. \(describe(error))")
        }
    }

    private func persist(_ next: LibraryDocument) throws {
        try repository.save(next)
        if localizer.language != next.settings.language { localizer = AppLocalizer(language: next.settings.language) }
        document = next
    }

    private func withLibraryMutation<T>(_ operation: () throws -> T) throws -> T {
        guard storageProblem == nil else { throw ShuttleError.storage("The library is read-only until its load error is resolved.") }
        guard !isLibraryBusy && !isMutatingLibrary else { throw ShuttleError.storage("Wait for the current library operation to finish.") }
        return try withNativeInteraction {
            isMutatingLibrary = true
            defer { isMutatingLibrary = false }
            return try repository.withCredentialAccess(operation)
        }
    }


    func save(_ profile: ServerProfile, password: String?, privateKey: String? = nil) throws {
        var candidate = profile
        if privateKey != nil {
            // Validate metadata before a pasted key has a file path.
            candidate.identity = .none
            candidate.identityFile = ""
        }
        var validated = try candidate.validated()
        try withLibraryMutation {
            let current = try repository.load()
            let keyStore: PrivateKeyFileStore?
            let createdKey: URL?
            if let privateKey {
                let store = PrivateKeyFileStore(directory: repository.directory.appendingPathComponent("keys", isDirectory: true))
                let url = try store.create(from: privateKey)
                keyStore = store
                createdKey = url
                validated.identity = .privateKey
                validated.identityFile = url.path
            } else {
                keyStore = nil
                createdKey = nil
            }
            var committed = false
            defer {
                if !committed, let keyStore, let createdKey {
                    do { try keyStore.removeCreatedFile(at: createdKey) }
                    catch {
                        let warning = text("Saving failed, and the newly entered private-key file could not be removed. Review \(createdKey.path).")
                        errorMessage = errorMessage.map { $0 + "\n" + warning } ?? warning
                    }
                }
            }
            let existingIndex = current.profiles.firstIndex { $0.id == validated.id }
            var next = current
            if let existingIndex { next.profiles[existingIndex] = validated }
            else { next.profiles.append(validated) }

            let changesPassword = validated.passwordMode == .keychain && !(password ?? "").isEmpty
            let previousPassword = changesPassword ? try credentials.password(for: validated.id) : nil
            if validated.passwordMode == .keychain && !changesPassword {
                guard try credentials.containsPassword(for: validated.id) else {
                    throw ShuttleError.credentials("Enter a password to save it in macOS Keychain.")
                }
            }
            do {
                if changesPassword, let password { try credentials.setPassword(password, for: validated.id) }
                try persist(next)
                committed = true
            } catch {
                if changesPassword {
                    do {
                        if let previousPassword { try credentials.setPassword(previousPassword, for: validated.id) }
                        else { try credentials.deletePassword(for: validated.id) }
                    } catch {
                        errorMessage = text("Saving failed, and the previous Keychain state could not be restored. Review this server’s credential in Keychain Access.")
                    }
                }
                throw error
            }
            if existingIndex != nil && validated.passwordMode != .keychain {
                do { try credentials.deletePassword(for: validated.id) }
                catch { errorMessage = text("Server saved, but its old password could not be removed from Keychain: \(describe(error))") }
            }
        }
    }

    func remove(_ profile: ServerProfile) {
        do {
            try withLibraryMutation {
                var next = try repository.load()
                next.profiles.removeAll { $0.id == profile.id }
                try persist(next)
                do { try credentials.deletePassword(for: profile.id) }
                catch { errorMessage = text("Server removed, but its saved password remains in Keychain Access under \(CredentialStore.defaultService). \(describe(error))") }
            }
        } catch { errorMessage = describe(error) }
    }

    func removeAllServers() async -> Bool {
        guard storageProblem == nil else {
            errorMessage = text("The library is read-only until its load error is resolved.")
            return false
        }
        guard !isLibraryBusy && !isMutatingLibrary else {
            errorMessage = text("Wait for the current library operation to finish.")
            return false
        }
        guard !profiles.isEmpty else { return false }
        isDeletingServers = true
        errorMessage = nil
        var succeeded = false
        defer {
            isDeletingServers = false
            if succeeded && errorMessage == nil && canDismissPopover { nativeInteractionEnded?() }
        }
        let repository = repository
        let credentials = credentials
        let libraryWorker = libraryWorker
        do {
            let (next, cleanupFailed) = try await Task.detached(priority: .userInitiated) {
                try await libraryWorker.perform {
                    try repository.withCredentialAccess {
                        var next = try repository.load()
                        let removed = next.profiles
                        next.profiles.removeAll()
                        try repository.save(next)
                        var cleanupFailed = false
                        for profile in removed {
                            do { try credentials.deletePassword(for: profile.id) }
                            catch { cleanupFailed = true }
                        }
                        return (next, cleanupFailed)
                    }
                }
            }.value
            if localizer.language != next.settings.language { localizer = AppLocalizer(language: next.settings.language) }
            document = next
            errorMessage = cleanupFailed
                ? text("Servers were deleted, but some saved passwords could not be removed from Keychain. Review entries under \(CredentialStore.defaultService).")
                : nil
            succeeded = true
            return true
        } catch {
            errorMessage = describe(error)
            return false
        }
    }

    func toggleFavorite(_ profile: ServerProfile) {
        do {
            try withLibraryMutation {
                var next = try repository.load()
                guard let index = next.profiles.firstIndex(where: { $0.id == profile.id }) else { return }
                next.profiles[index].isFavorite.toggle()
                try persist(next)
            }
        } catch { errorMessage = describe(error) }
    }

    func duplicate(_ profile: ServerProfile) -> ServerProfile {
        var copy = profile
        copy.id = UUID()
        copy.name = text("\(profile.name) Copy")
        if copy.passwordMode == .keychain { copy.passwordMode = .askWhenNeeded }
        return copy
    }

    func updateSettings(_ settings: AppSettings) {
        let previous = document.settings
        let changesShortcut = settings.globalShortcutEnabled != previous.globalShortcutEnabled
        var shortcutWasApplied = false
        do {
            try withLibraryMutation {
                var next = try repository.load()
                next.settings = settings
                if !settings.terminal.supportsTabs { next.settings.openMode = .window }
                if changesShortcut {
                    try settingsChanged?(next.settings)
                    shortcutWasApplied = true
                }
                try persist(next)
            }
        } catch {
            let savingError = describe(error)
            errorMessage = savingError
            if shortcutWasApplied {
                do { try settingsChanged?(previous) }
                catch { errorMessage = text("Saving failed: \(savingError)\nThe previous global shortcut could not be restored: \(describe(error))") }
            }
        }
    }

    private nonisolated static func sameConnection(_ lhs: ServerProfile, _ rhs: ServerProfile) -> Bool {
        lhs.host.caseInsensitiveCompare(rhs.host) == .orderedSame && lhs.user == rhs.user &&
        lhs.port == rhs.port && lhs.identityFile == rhs.identityFile && lhs.sshConfigPath == rhs.sshConfigPath
    }

    func isDuplicate(_ candidate: ServerProfile) -> Bool {
        profiles.contains { Self.sameConnection($0, candidate) }
    }

    func isBackupConflict(_ candidate: ServerProfile) -> Bool {
        profiles.contains {
            $0.host.caseInsensitiveCompare(candidate.host) == .orderedSame &&
            $0.user == candidate.user && $0.port == candidate.port
        }
    }

    private nonisolated static func performInBackground<T: Sendable>(
        on libraryWorker: LibraryWorker,
        _ operation: @escaping @Sendable () throws -> T
    ) async throws -> T {
        let worker = Task.detached(priority: .userInitiated) {
            try await libraryWorker.perform {
                try Task.checkCancellation()
                return try operation()
            }
        }
        return try await withTaskCancellationHandler {
            try await worker.value
        } onCancel: {
            worker.cancel()
        }
    }

    private nonisolated static func protectExportDestination(
        _ destination: URL, repository: ProfileRepository, profiles: [ServerProfile]
    ) throws {
        guard destination.isFileURL, !destination.path.utf8.contains(0) else {
            throw ShuttleError.storage("Choose a local file for the export.")
        }
        var protected = [repository.fileURL,
                         repository.directory.appendingPathComponent(".library.lock"),
                         repository.directory.appendingPathComponent(".credentials.lock")]
        for profile in profiles {
            if !profile.identityFile.isEmpty {
                protected.append(URL(fileURLWithPath: (profile.identityFile as NSString).expandingTildeInPath))
            }
            if let path = profile.sshConfigPath {
                protected.append(URL(fileURLWithPath: (path as NSString).expandingTildeInPath))
            }
        }
        let resolved = destination.standardizedFileURL.resolvingSymlinksInPath()
        var destinationInfo = stat()
        let destinationExists = stat(destination.path, &destinationInfo) == 0
        for source in protected {
            var sourceInfo = stat()
            let sameFile = destinationExists && stat(source.path, &sourceInfo) == 0 &&
                destinationInfo.st_dev == sourceInfo.st_dev && destinationInfo.st_ino == sourceInfo.st_ino
            if resolved == source.standardizedFileURL.resolvingSymlinksInPath() || sameFile {
                throw ShuttleError.storage("Choose an export destination other than the active library, its lock files, or a referenced private key or SSH configuration.")
            }
        }
    }

    func exportConnections(to url: URL, backupPassword: String?) async throws {
        guard storageProblem == nil else { throw ShuttleError.storage("The library is read-only until its load error is resolved.") }
        guard !isLibraryBusy && !isMutatingLibrary else { throw ShuttleError.storage("Wait for the current library operation to finish.") }
        isProcessingBackup = true
        defer { isProcessingBackup = false }
        let repository = repository
        let credentials = credentials
        try await Self.performInBackground(on: libraryWorker) {
            try repository.withCredentialAccess {
                try Task.checkCancellation()
                let current = try repository.load()
                try Self.protectExportDestination(url, repository: repository, profiles: current.profiles)
                if let backupPassword {
                    try EncryptedBackup.exportProfiles(current.profiles, password: backupPassword, to: url) {
                        try credentials.password(for: $0)
                    }
                } else {
                    try Task.checkCancellation()
                    try ConnectionExporter.exportProfiles(current.profiles, to: url)
                }
            }
        }
    }

    func unlockBackup(from url: URL, password: String) async throws -> ImportResult {
        guard !isLibraryBusy && !isMutatingLibrary else { throw ShuttleError.storage("Wait for the current library operation to finish.") }
        isProcessingBackup = true
        defer { isProcessingBackup = false }
        return try await Self.performInBackground(on: libraryWorker) {
            let result = try EncryptedBackup.importProfiles(from: url, password: password)
            try Task.checkCancellation()
            return result
        }
    }

    func importCandidates(_ candidates: [ImportCandidate], allowDuplicates: Bool = false) async throws {
        guard storageProblem == nil else { throw ShuttleError.storage("Resolve the library load error before importing.") }
        guard !isLibraryBusy && !isMutatingLibrary else { throw ShuttleError.storage("Wait for the current library operation to finish.") }
        var succeeded = false
        isImporting = true
        defer {
            isImporting = false
            if succeeded && errorMessage == nil && canDismissPopover { nativeInteractionEnded?() }
        }
        let repository = repository
        let credentials = credentials
        let next = try await Self.performInBackground(on: libraryWorker) {
            try repository.withCredentialAccess {
                try Task.checkCancellation()
                var next = try repository.load()
                var identifiers = Set<UUID>()
                // Validate the entire selection before creating files or touching credentials.
                for candidate in candidates {
                    guard identifiers.insert(candidate.id).inserted else {
                        throw ShuttleError.importFailure("The import contains duplicate server identifiers. Nothing was imported.")
                    }
                    guard !candidate.requiresSSHConfiguration else {
                        throw ShuttleError.importFailure("Choose and trust an SSH configuration for every selected server that requires one before importing.")
                    }
                    if candidate.privateKey != nil && candidate.profile.identity != .privateKey {
                        throw ShuttleError.importFailure("The bundled private key does not match the server’s authentication mode.")
                    }
                    _ = try candidate.profile.validated()
                }
                let keyStore = PrivateKeyFileStore(directory: repository.directory.appendingPathComponent("keys", isDirectory: true))
                var createdKeys: [URL] = []
                var createdCredentials: [UUID] = []
                do {
                    for candidate in candidates {
                        try Task.checkCancellation()
                        var profile = try candidate.profile.validated()
                        if !allowDuplicates && next.profiles.contains(where: {
                            $0.id == profile.id || Self.sameConnection($0, profile)
                        }) { continue }
                        if profile.passwordMode == .keychain && (candidate.password ?? "").isEmpty {
                            throw ShuttleError.credentials("Enter a password to save it in macOS Keychain.")
                        }
                        // An explicit duplicate is a new record; orphan credentials also belong to
                        // their original identifier and must never be claimed by an import.
                        while try next.profiles.contains(where: { $0.id == profile.id }) ||
                                credentials.containsPassword(for: profile.id) {
                            profile.id = UUID()
                        }
                        if let data = candidate.privateKey {
                            guard data.count <= 1_048_576, let text = String(data: data, encoding: .utf8) else {
                                throw ShuttleError.importFailure("The bundled private key must be valid UTF-8 and no larger than 1 MiB.")
                            }
                            let keyURL = try keyStore.create(from: text)
                            createdKeys.append(keyURL)
                            profile.identityFile = keyURL.path
                        }
                        if let password = candidate.password, profile.passwordMode == .keychain {
                            guard try credentials.password(for: profile.id) == nil else {
                                throw ShuttleError.credentials("A saved credential already uses this server identifier. Nothing was imported.")
                            }
                            // Register first: a credential boundary may write and then throw.
                            createdCredentials.append(profile.id)
                            try credentials.setPassword(password, for: profile.id)
                        }
                        next.profiles.append(profile)
                    }
                    try Task.checkCancellation()
                    try repository.save(next)
                    return next
                } catch {
                    var credentialRollbackFailed = false
                    var keyRollbackFailed = false
                    for id in createdCredentials.reversed() {
                        do { try credentials.deletePassword(for: id) }
                        catch { credentialRollbackFailed = true }
                    }
                    for url in createdKeys.reversed() {
                        do { try keyStore.removeCreatedFile(at: url) }
                        catch { keyRollbackFailed = true }
                    }
                    if credentialRollbackFailed || keyRollbackFailed {
                        let localizer = AppLocalizer(language: next.settings.language)
                        var message = localizer.error(error)
                        if credentialRollbackFailed {
                            message += "\n" + localizer.text("Import failed, and the previous Keychain state could not be restored. Review entries under \(CredentialStore.defaultService).")
                        }
                        if keyRollbackFailed {
                            message += "\n" + localizer.text("Import failed, and newly created private-key files could not all be removed. Review \(keyStore.directory.path).")
                        }
                        throw ShuttleError.storage("\(message)")
                    }
                    throw error
                }
            }
        }
        if localizer.language != next.settings.language { localizer = AppLocalizer(language: next.settings.language) }
        document = next
        succeeded = true
    }

    func connect(_ profile: ServerProfile) {
        guard !isOpeningConnection && !isLibraryBusy && !isMutatingLibrary else { return }
        do { _ = try profile.validated() }
        catch { errorMessage = describe(error); return }
        isOpeningConnection = true
        dismissPopover?()
        let settings = self.settings
        let directory = repository.directory
        Task {
            do {
                try await Task.detached(priority: .userInitiated) {
                    try TerminalLauncher.launch(profileID: profile.id, library: directory, settings: settings)
                }.value
            } catch { errorMessage = describe(error); presentPopover?() }
            isOpeningConnection = false
        }
    }

    func revealLibrary() {
        let target = FileManager.default.fileExists(atPath: repository.directory.path) ? repository.directory : repository.directory.deletingLastPathComponent()
        NSWorkspace.shared.open(target)
    }
}

// Blocking credential and filesystem work must not occupy cooperative executor threads.
private actor LibraryWorker {
    private final class Executor: SerialExecutor {
        private let queue = DispatchQueue(label: "com.fatihakdogan.ShuttleNext.library", qos: .userInitiated)

        func enqueue(_ job: consuming ExecutorJob) {
            let job = UnownedJob(job)
            let executor = asUnownedSerialExecutor()
            queue.async { job.runSynchronously(on: executor) }
        }
    }

    private nonisolated let executor = Executor()
    nonisolated var unownedExecutor: UnownedSerialExecutor { executor.asUnownedSerialExecutor() }

    func perform<T: Sendable>(_ operation: @Sendable () throws -> T) rethrows -> T {
        try operation()
    }
}
