import AppKit
import SwiftUI
import ShuttleCore

struct ImportPreviewView: View {
    @ObservedObject var model: AppModel
    let onClose: () -> Void
    let result: ImportResult
    @State private var selection: Set<UUID>
    @State private var noticesExpanded = true
    @State private var configurations: [UUID: String] = [:]
    let sourceName: String

    init(model: AppModel, result: ImportResult, sourceName: String, onClose: @escaping () -> Void) {
        self.model = model
        self.onClose = onClose
        self.result = result
        _selection = State(initialValue: Set(result.candidates.filter {
            result.isEncryptedBackup
                ? !model.isBackupConflict($0.profile) && !$0.requiresSSHConfiguration
                : !model.isDuplicate($0.profile)
        }.map(\.id)))
        self.sourceName = sourceName
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Image(systemName: "square.and.arrow.down").font(.title).foregroundStyle(.tint)
                VStack(alignment: .leading) {
                    Text(model.text("Review Import")).font(.title2.bold())
                    Text(sourceName).lineLimit(1).truncationMode(.middle).foregroundStyle(.secondary)
                }
                Spacer()
                Text(model.text("\(selection.count) selected")).font(.callout).foregroundStyle(.secondary)
            }
            Text(model.text("Nothing is changed until you confirm. Existing servers are not overwritten.")).font(.callout).foregroundStyle(.secondary)
            if result.isEncryptedBackup {
                Label(model.text("Protected backup: selected passwords go to Keychain and bundled keys are restored as private files. The encrypted source stays unchanged."), systemImage: "lock.shield")
                    .font(.callout).foregroundStyle(.secondary)
                if result.candidates.contains(where: { model.isBackupConflict($0.profile) }) {
                    Text(model.text("Matching server: selected entries are added as separate copies, never used to update existing servers."))
                        .font(.caption).foregroundStyle(.primary)
                }
            }
            Group {
                if result.candidates.isEmpty {
                    Label(model.text("No supported server entries were found."), systemImage: "info.circle")
                        .font(.callout).foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                        .padding(16)
                } else {
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 0) {
                            ForEach(result.candidates) { candidate in
                                candidateRow(candidate).padding(.horizontal, 8).padding(.vertical, 6)
                                if candidate.id != result.candidates.last?.id { Divider().padding(.leading, 34) }
                            }
                        }.padding(4)
                    }
                }
            }
            .background(.quaternary.opacity(0.35), in: RoundedRectangle(cornerRadius: 8))
            if !result.isEncryptedBackup && result.candidates.contains(where: { $0.password != nil }) {
                Label {
                    Text(model.text("This file contains plaintext passwords. Selected passwords will be stored in Keychain, not copied into the library. The original file is left untouched."))
                        .foregroundStyle(.primary)
                } icon: {
                    Image(systemName: "exclamationmark.shield").foregroundStyle(.orange)
                }.font(.callout)
            }
            if !result.warnings.isEmpty {
                DisclosureGroup(model.text("\(result.warnings.count) import notices"), isExpanded: $noticesExpanded) {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 8) {
                            ForEach(Array(result.warnings.enumerated()), id: \.offset) { _, warning in Text(model.text(warning)).font(.caption).frame(maxWidth: .infinity, alignment: .leading) }
                        }
                    }.frame(maxHeight: 100)
                }
            }
            HStack {
                Button(model.text("Cancel"), action: onClose).keyboardShortcut(.cancelAction)
                Spacer()
                Button(model.isImporting ? model.text("Importing…") : model.text("Import \(selection.count) Servers"), action: commit)
                    .buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction)
                    .disabled(selection.isEmpty || model.storageProblem != nil || model.isLibraryBusy)
            }
        }
        .padding(16)
        .disabled(model.isLibraryBusy)
    }

    private func candidateRow(_ candidate: ImportCandidate) -> some View {
        let duplicate = !result.isEncryptedBackup && model.isDuplicate(candidate.profile)
        let conflict = result.isEncryptedBackup && model.isBackupConflict(candidate.profile)
        let unresolved = candidate.requiresSSHConfiguration && configurations[candidate.id] == nil
        return HStack(alignment: .top, spacing: 12) {
            Toggle(isOn: Binding(get: { selection.contains(candidate.id) }, set: {
                if $0 { selection.insert(candidate.id) } else { selection.remove(candidate.id) }
            })) { EmptyView() }
                .labelsHidden().toggleStyle(.checkbox).disabled(duplicate || unresolved)
                .accessibilityLabel(conflict ? model.text("Add as Separate Copy") + ": " + candidate.profile.name : model.text("Import \(candidate.profile.name)"))
            VStack(alignment: .leading, spacing: 5) {
                Text(candidate.profile.name).fontWeight(.medium).lineLimit(1)
                Text(verbatim: "\(candidate.profile.group.isEmpty ? model.text("Ungrouped") : candidate.profile.group) · \(candidate.profile.destination)")
                    .font(.caption).foregroundStyle(.secondary).lineLimit(1)
                if conflict {
                    Label {
                        Text(model.text("Add as Separate Copy")).foregroundStyle(.primary)
                    } icon: {
                        Image(systemName: "plus.square.on.square").foregroundStyle(.orange)
                    }.font(.caption)
                }
                if result.isEncryptedBackup {
                    if candidate.password != nil {
                        Label(model.text("Bundled Password"), systemImage: "key.fill").font(.caption).foregroundStyle(.secondary)
                    }
                    if candidate.privateKey != nil {
                        Label(model.text("Bundled Private Key"), systemImage: "doc.fill").font(.caption).foregroundStyle(.secondary)
                    }
                    if candidate.requiresSSHConfiguration {
                        Text(model.text(unresolved ? "SSH Configuration Required" : "Configuration Selected"))
                            .font(.caption).foregroundStyle(unresolved ? .primary : .secondary)
                        if let path = configurations[candidate.id] {
                            Text(path).font(.caption2).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                        }
                        Button(model.text("Choose SSH Configuration")) { chooseConfiguration(for: candidate.id) }
                            .controlSize(.small)
                    }
                } else if duplicate {
                    Text(model.text("Already imported")).font(.caption).foregroundStyle(.secondary)
                } else if candidate.password != nil {
                    Label(model.text("To Keychain"), systemImage: "key.fill").font(.caption).foregroundStyle(.secondary)
                }
            }
            Spacer(minLength: 0)
        }.padding(.vertical, 4)
    }

    private func chooseConfiguration(for id: UUID) {
        guard !model.isLibraryBusy else { return }
        let panel = NSOpenPanel()
        panel.title = model.text("Choose SSH Configuration")
        panel.message = model.text("Select an SSH configuration file you trust on this Mac. Its external dependencies are not copied.")
        panel.prompt = model.text("Choose")
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.showsHiddenFiles = true
        guard model.withNativeInteraction({ panel.runModal() }) == .OK, let url = panel.url else { return }
        do {
            let resolved = url.resolvingSymlinksInPath().standardizedFileURL
            let values = try resolved.resourceValues(forKeys: [.isRegularFileKey])
            guard values.isRegularFile == true, FileManager.default.isReadableFile(atPath: resolved.path) else {
                throw ShuttleError.storage("Choose a readable SSH configuration file.")
            }
            configurations[id] = resolved.path
        } catch { model.errorMessage = model.describe(error) }
    }

    private func commit() {
        guard !model.isLibraryBusy else { return }
        model.errorMessage = nil
        let candidates = result.candidates.filter { selection.contains($0.id) }.map { candidate in
            var resolved = candidate
            if let path = configurations[candidate.id] {
                resolved.profile.sshConfigPath = path
                resolved.requiresSSHConfiguration = false
            }
            return resolved
        }
        Task {
            do {
                try await model.importCandidates(candidates, allowDuplicates: result.isEncryptedBackup)
                onClose()
            } catch { model.errorMessage = model.text("Import failed. \(model.describe(error))") }
        }
    }
}
