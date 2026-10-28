import AppKit
import SwiftUI
import ShuttleCore
import UniformTypeIdentifiers

extension UTType {
    static let shuttleNextBackup = UTType(exportedAs: "com.fatihakdogan.ShuttleNext.backup", conformingTo: .data)
}

struct BackupExportView: View {
    @ObservedObject var model: AppModel
    let onClose: () -> Void
    @State private var includeSecrets = false
    @State private var password = ""
    @State private var confirmation = ""
    @State private var error: String?

    private var validPassword: Bool {
        password.count >= 12 && password.utf8.count <= 1024 && password == confirmation
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label(model.text("Export Connections"), systemImage: "square.and.arrow.up").font(.title3.bold())
            VStack(alignment: .leading, spacing: 10) {
                Toggle(model.text("Include passwords and private-key files"), isOn: $includeSecrets)
                    .toggleStyle(.checkbox)
                    .help(model.text("Includes each server’s saved password and selected private-key file. Existing encrypted keys still need their own passphrases."))
                if includeSecrets {
                    PasswordField(title: model.text("Backup Password"), text: $password, localizer: model.localizer)
                    PasswordField(title: model.text("Confirm Backup Password"), text: $confirmation, localizer: model.localizer)
                    Text(model.text("Use at least 12 characters. Keep this password safe; it cannot be recovered."))
                        .font(.caption).foregroundStyle(.secondary)
                    Text(model.text("Encrypted backup. SSH config, agent identities and hardware keys are not included."))
                        .font(.caption).foregroundStyle(.secondary)
                        .help(model.text("SSH configuration files, agent/default identities, and hardware keys are not bundled. You must resolve external dependencies on the destination Mac."))
                    if !password.isEmpty && (password.count < 12 || password.utf8.count > 1024) {
                        Text(model.text("Backup passwords must contain at least 12 characters and at most 1024 UTF-8 bytes."))
                            .font(.caption).foregroundStyle(.primary)
                    } else if !confirmation.isEmpty && password != confirmation {
                        Text(model.text("Passwords do not match.")).font(.caption).foregroundStyle(.primary)
                    }
                } else {
                    Text(model.text("Exports connection details only. Passwords and private-key files are not included."))
                        .font(.caption).foregroundStyle(.secondary)
                }
                if let error {
                    Label {
                        Text(error).foregroundStyle(.primary)
                    } icon: {
                        Image(systemName: "exclamationmark.triangle").foregroundStyle(.orange)
                    }
                }
            }.font(.callout)
            HStack {
                Button(model.text("Cancel"), action: close).keyboardShortcut(.cancelAction)
                Spacer()
                Button(model.text(model.isProcessingBackup ? "Exporting…" : "Export"), action: export)
                    .buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction)
                    .disabled(includeSecrets && !validPassword)
            }.padding(.top, 4)
        }
        .padding(16)
        .disabled(model.isLibraryBusy)
        .onChange(of: includeSecrets) { _, _ in clearSecrets(); error = nil }
        .onDisappear(perform: clearSecrets)
    }

    private func clearSecrets() { password = ""; confirmation = "" }

    private func close() {
        guard !model.isLibraryBusy else { return }
        clearSecrets()
        onClose()
    }

    private func export() {
        guard !model.isLibraryBusy, !includeSecrets || validPassword else { return }
        let backupPassword = includeSecrets ? password : nil
        let panel = NSSavePanel()
        panel.title = model.text("Export Connections")
        panel.prompt = model.text("Export")
        panel.allowedContentTypes = includeSecrets ? [.shuttleNextBackup] : [.json]
        panel.nameFieldStringValue = includeSecrets ? "ShuttleNext-backup.shuttlenext" : model.text("ShuttleNext-connections.json")
        panel.canCreateDirectories = true
        guard model.withNativeInteraction({ panel.runModal() }) == .OK, let url = panel.url else { return }
        error = nil
        Task {
            do {
                try await model.exportConnections(to: url, backupPassword: backupPassword)
                clearSecrets()
                onClose()
            } catch { self.error = model.describe(error) }
        }
    }
}

struct BackupUnlockView: View {
    @ObservedObject var model: AppModel
    let url: URL
    let onClose: () -> Void
    let onUnlocked: (ImportResult) -> Void
    @State private var password = ""
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Label(model.text("Unlock Backup"), systemImage: "lock.shield").font(.title2.bold())
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    Text(url.lastPathComponent).lineLimit(2).truncationMode(.middle).foregroundStyle(.secondary)
                    Text(model.text("Enter the password used to encrypt this backup. Nothing is restored until you review and confirm."))
                    PasswordField(title: model.text("Backup Password"), text: $password, localizer: model.localizer)
                    if password.utf8.count > 1024 {
                        Text(model.text("Backup passwords must contain at most 1024 UTF-8 bytes.")).font(.caption).foregroundStyle(.primary)
                    }
                    if let error {
                        Label {
                            Text(error).foregroundStyle(.primary)
                        } icon: {
                            Image(systemName: "exclamationmark.triangle").foregroundStyle(.orange)
                        }
                    }
                }.font(.callout)
            }
            HStack {
                Button(model.text("Cancel")) {
                    guard !model.isLibraryBusy else { return }
                    password = ""
                    onClose()
                }.keyboardShortcut(.cancelAction)
                Spacer()
                Button(model.text(model.isProcessingBackup ? "Unlocking…" : "Unlock"), action: unlock)
                    .buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction)
                    .disabled(password.isEmpty || password.utf8.count > 1024)
            }
        }.padding(16)
            .disabled(model.isLibraryBusy)
            .onDisappear { password = "" }
    }

    private func unlock() {
        guard !model.isLibraryBusy, !password.isEmpty, password.utf8.count <= 1024 else { return }
        let backupPassword = password
        error = nil
        Task {
            do {
                let result = try await model.unlockBackup(from: url, password: backupPassword)
                password = ""
                onUnlocked(result)
            } catch { self.error = model.describe(error) }
        }
    }
}
