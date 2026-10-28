import AppKit
import SwiftUI
import ShuttleCore

struct MenuBarView: View {
    @ObservedObject var model: AppModel
    let maximumHeight: CGFloat
    let navigationChanged: (CGFloat) -> Void
    @State private var screen: Screen = .connections
    @State private var exportHeight: CGFloat = 160

    private enum Screen {
        case connections
        case edit(ServerProfile)
        case preview(ImportResult, String)
        case export
        case unlock(URL)
        case settings
        case delete(ServerProfile)
        case deleteAll
    }

    private var presentationHeight: CGFloat {
        switch screen {
        case .settings:
            let height: CGFloat = model.storageProblem == nil ? 440 : maximumHeight
            return min(maximumHeight, height + (model.errorMessage == nil ? 0 : 100))
        case .delete, .deleteAll:
            return min(maximumHeight, 340 + (model.errorMessage == nil ? 0 : 100))
        case .export:
            let bannerHeight: CGFloat = (model.isLibraryBusy ? 44 : 0) + (model.errorMessage == nil ? 0 : 100)
            return min(maximumHeight, exportHeight + bannerHeight)
        case .connections:
            break
        default:
            return maximumHeight
        }
        var groups = Set<String>()
        var favorites = false
        for profile in model.profiles {
            if profile.isFavorite { favorites = true }
            else { groups.insert(profile.group) }
        }
        let sections = groups.count + (favorites ? 1 : 0)
        let listHeight = model.profiles.isEmpty ? 320 : CGFloat(100 + model.profiles.count * 46 + sections * 27)
        let rootHeight = model.storageProblem != nil ? 320 : listHeight
        return min(maximumHeight, rootHeight + (model.errorMessage == nil ? 0 : 100))
    }

    var body: some View {
        let height = presentationHeight
        VStack(spacing: 0) {
            if model.isLibraryBusy {
                HStack {
                    ProgressView().controlSize(.small)
                    Text(model.text(model.isProcessingBackup ? "Processing backup…" : (model.isDeletingServers
                                    ? "Deleting servers… Keychain may ask for access."
                                    : "Importing connections… Keychain may ask for access."))).font(.callout)
                    Spacer()
                }.padding(12)
                Divider()
            }
            if let error = model.errorMessage {
                HStack(alignment: .top) {
                    Label {
                        Text(error).foregroundStyle(.primary)
                    } icon: {
                        Image(systemName: "exclamationmark.triangle").foregroundStyle(.orange)
                    }.font(.caption)
                    Spacer(minLength: 4)
                    Button { model.errorMessage = nil } label: { Image(systemName: "xmark") }
                        .buttonStyle(.plain).accessibilityLabel(model.text("Dismiss error"))
                }.padding(12)
                Divider()
            }
            switch screen {
            case .connections:
                QuickConnectView(model: model,
                                 add: { screen = .edit(ServerProfile()) },
                                 edit: { screen = .edit($0) },
                                 remove: { screen = .delete($0) },
                                 importFile: chooseImport,
                                 exportFile: chooseExport,
                                 settings: { screen = .settings })
            case .edit(let profile):
                ServerEditorView(model: model, profile: profile, onClose: back).id(profile.id)
            case .preview(let result, let name):
                ImportPreviewView(model: model, result: result, sourceName: name, onClose: back)
            case .export:
                ScrollView {
                    BackupExportView(model: model, onClose: back)
                        .fixedSize(horizontal: false, vertical: true)
                        .onGeometryChange(for: CGFloat.self, of: { $0.size.height }) { exportHeight = ceil($0) }
                }
            case .unlock(let url):
                BackupUnlockView(model: model, url: url, onClose: back, onUnlocked: {
                    screen = .preview($0, url.lastPathComponent)
                })
            case .settings:
                HStack(spacing: 10) {
                    Button(action: back) { Image(systemName: "chevron.left").frame(width: 28, height: 28) }
                        .buttonStyle(.borderless).keyboardShortcut(.cancelAction)
                        .help(model.text("Back")).accessibilityLabel(model.text("Back"))
                    Text(model.text("Settings")).font(.title3.bold())
                    Spacer()
                }.padding(.horizontal, 16).padding(.vertical, 12)
                Divider()
                SettingsView(model: model, deleteAllServers: {
                    guard !model.isLibraryBusy, model.storageProblem == nil, !model.profiles.isEmpty else { return }
                    screen = .deleteAll
                })
            case .delete(let profile):
                VStack(alignment: .leading, spacing: 18) {
                    Label(model.text("Remove Server?"), systemImage: "trash").font(.title2.bold())
                    Text(profile.name).font(.headline)
                    Text(model.text("Only this entry and its saved Keychain password are removed. Your SSH configuration and key files stay untouched."))
                        .foregroundStyle(.secondary)
                    Spacer()
                    HStack {
                        Button(model.text("Cancel"), action: back).keyboardShortcut(.cancelAction)
                        Spacer()
                        Button(model.text("Remove Server"), role: .destructive) { model.remove(profile); back() }
                            .buttonStyle(.borderedProminent)
                    }
                }.padding(20)
            case .deleteAll:
                VStack(alignment: .leading, spacing: 18) {
                    Label(model.text("Delete All Servers?"), systemImage: "trash").font(.title2.bold())
                    Text(model.text("All server entries and their saved passwords will be deleted. Your settings, SSH configuration, and private-key files will stay unchanged. This cannot be undone."))
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    Spacer(minLength: 0)
                    HStack {
                        Button(model.text("Cancel"), action: cancelDeleteAll)
                            .keyboardShortcut(.cancelAction)
                        Spacer()
                        Button(model.text("Delete \(model.profiles.count) Servers"), role: .destructive, action: deleteAllServers)
                            .buttonStyle(.borderedProminent)
                            .tint(.red)
                            .disabled(model.profiles.isEmpty || model.storageProblem != nil || model.isLibraryBusy)
                    }
                }
                .padding(20)
            }
        }
        .frame(height: height)
        .disabled(model.isLibraryBusy)
        .environment(\.locale, model.localizer.locale)
        .onAppear { navigationChanged(height) }
        .onChange(of: height) { _, value in navigationChanged(value) }
    }

    private func back() {
        guard !model.isLibraryBusy else { return }
        screen = .connections
    }

    private func cancelDeleteAll() {
        guard !model.isLibraryBusy else { return }
        screen = .settings
    }

    private func deleteAllServers() {
        guard !model.isLibraryBusy, model.storageProblem == nil, !model.profiles.isEmpty else { return }
        Task {
            if await model.removeAllServers() { screen = .connections }
        }
    }

    private func chooseImport() {
        guard !model.isLibraryBusy else { return }
        let panel = NSOpenPanel()
        panel.title = model.text("Import Connections")
        panel.prompt = model.text("Preview Import")
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.showsHiddenFiles = true
        guard model.withNativeInteraction({ panel.runModal() }) == .OK, let url = panel.url else { return }
        do {
            let backupURL = url.resolvingSymlinksInPath().standardizedFileURL
            if try EncryptedBackup.isBackup(at: backupURL) {
                screen = .unlock(backupURL)
            } else {
                let result = try ConnectionImporter.importProfiles(from: url)
                screen = .preview(result, url.lastPathComponent)
            }
        } catch { model.errorMessage = model.describe(error) }
    }

    private func chooseExport() {
        guard !model.isLibraryBusy else { return }
        exportHeight = 160
        screen = .export
    }
}
