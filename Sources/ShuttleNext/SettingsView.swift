import AppKit
import SwiftUI
import ShuttleCore

struct SettingsView: View {
    @ObservedObject var model: AppModel
    let deleteAllServers: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    VStack(alignment: .leading, spacing: 16) {
                        VStack(alignment: .leading, spacing: 10) {
                            heading(model.text("Appearance"))
                            HStack(spacing: 16) {
                                Text(model.text("Language"))
                                Spacer(minLength: 0)
                                Picker(model.text("Language"), selection: setting(\.language)) {
                                    ForEach(AppLanguage.allCases) { language in
                                        Text(language == .system ? model.text("System") : language.nativeName).tag(language)
                                    }
                                }
                                .labelsHidden()
                                .frame(maxWidth: 230, alignment: .trailing)
                            }
                        }
                        Divider()
                        VStack(alignment: .leading, spacing: 10) {
                            heading(model.text("Connections"))
                            terminalSelection
                            if model.settings.terminal.supportsTabs && model.availableTerminals.contains(model.settings.terminal) {
                                HStack(spacing: 16) {
                                    Text(model.text("Open as"))
                                    Spacer(minLength: 0)
                                    Picker(model.text("Open as"), selection: setting(\.openMode)) {
                                        ForEach(TerminalOpenMode.allCases) { mode in Text(openModeTitle(mode)).tag(mode) }
                                    }
                                    .labelsHidden()
                                    .frame(maxWidth: 230, alignment: .trailing)
                                }
                            }
                        }
                        Divider()
                        VStack(alignment: .leading, spacing: 10) {
                            heading(model.text("Quick Access"))
                            Toggle(isOn: setting(\.globalShortcutEnabled)) {
                                Text(model.text("Global shortcut: ⌘⇧K"))
                                    .frame(maxWidth: .infinity, alignment: .leading)
                            }
                            .toggleStyle(.switch)
                            .controlSize(.small)
                            Text(model.text("Open the server search from any app. Other apps may use the same shortcut."))
                                .font(.caption).foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                    .disabled(model.storageProblem != nil || model.isLibraryBusy)
                    if model.storageProblem != nil {
                        Divider()
                        VStack(alignment: .leading, spacing: 10) {
                            heading(model.text("Library Recovery"))
                            Text(model.text("The library could not be loaded. Restore or fix this file, then reload it."))
                                .foregroundStyle(.secondary)
                            Text(model.repository.fileURL.path)
                                .font(.caption.monospaced()).textSelection(.enabled)
                                .fixedSize(horizontal: false, vertical: true)
                            HStack {
                                Button(model.text("Show in Finder")) { model.revealLibrary() }
                                Button(model.text("Reload Library")) { model.reload() }
                            }
                        }
                    }
                }
                .font(.callout)
                .padding(16)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(minHeight: 0, maxHeight: .infinity)
            HStack {
                Spacer(minLength: 0)
                Button(model.text("Delete All Servers…"), role: .destructive, action: deleteAllServers)
                    .buttonStyle(.link)
                    .foregroundStyle(.red)
                    .disabled(model.profiles.isEmpty || model.storageProblem != nil || model.isLibraryBusy)
            }
            .font(.callout)
            .padding(.horizontal, 16).padding(.top, 8).padding(.bottom, 16)
        }
        .onAppear { model.refreshAvailableTerminals() }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            model.refreshAvailableTerminals()
        }
    }

    @ViewBuilder
    private var terminalSelection: some View {
        HStack(spacing: 16) {
            Text(model.text("Terminal"))
            Spacer(minLength: 0)
            Menu {
                ForEach(model.availableTerminals) { terminal in
                    Button {
                        guard model.availableTerminals.contains(terminal) else { return }
                        var settings = model.settings
                        settings.terminal = terminal
                        model.updateSettings(settings)
                    } label: {
                        if terminal == model.settings.terminal {
                            Label(terminal.title, systemImage: "checkmark")
                        } else {
                            Text(terminal.title)
                        }
                    }
                }
            } label: {
                Text(model.availableTerminals.contains(model.settings.terminal) ? model.settings.terminal.title : model.text("Choose"))
                    .lineLimit(1)
            }
            .menuStyle(.borderedButton)
            .accessibilityLabel(model.text("Terminal"))
            .accessibilityValue(model.availableTerminals.contains(model.settings.terminal) ? model.settings.terminal.title : model.text("Choose"))
            .frame(maxWidth: 230, alignment: .trailing)
            .disabled(model.availableTerminals.isEmpty)
        }
        if model.availableTerminals.isEmpty {
            Label {
                Text(model.text("No supported terminal was found.")).foregroundStyle(.primary)
            } icon: {
                Image(systemName: "exclamationmark.triangle").foregroundStyle(.orange)
            }.font(.caption)
        }
    }

    private func heading(_ title: String) -> some View {
        Text(title).font(.system(size: 10, weight: .semibold))
            .foregroundStyle(.secondary).textCase(.uppercase)
            .accessibilityAddTraits(.isHeader)
    }

    private func openModeTitle(_ mode: TerminalOpenMode) -> String {
        switch mode {
        case .window: model.text("New Window")
        case .tab: model.text("New Tab")
        }
    }

    private func setting<Value>(_ keyPath: WritableKeyPath<AppSettings, Value>) -> Binding<Value> {
        Binding(get: { model.settings[keyPath: keyPath] }, set: { value in
            var settings = model.settings
            settings[keyPath: keyPath] = value
            model.updateSettings(settings)
        })
    }
}
