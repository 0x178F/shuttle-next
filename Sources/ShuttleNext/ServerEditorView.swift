import AppKit
import SwiftUI
import ShuttleCore

struct ServerEditorView: View {
    @ObservedObject var model: AppModel
    let onClose: () -> Void
    @State private var profile: ServerProfile
    @State private var password = ""
    @State private var privateKey = ""
    @State private var isEnteringPrivateKey = false
    @State private var portText: String
    @State private var problem: Error?
    @State private var keepSavedPassword: Bool
    @State private var notesExpanded = true
    private let originallySavedPassword: Bool
    private let isNew: Bool

    init(model: AppModel, profile: ServerProfile, onClose: @escaping () -> Void) {
        self.model = model
        self.onClose = onClose
        _profile = State(initialValue: profile)
        _portText = State(initialValue: profile.port.map(String.init) ?? "")
        isNew = !model.profiles.contains { $0.id == profile.id }
        let savedPassword = !isNew && profile.passwordMode == .keychain
        originallySavedPassword = savedPassword
        _keepSavedPassword = State(initialValue: savedPassword)
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                Image(systemName: "server.rack")
                    .font(.title3).foregroundStyle(.tint)
                    .frame(width: 24, height: 28)
                VStack(alignment: .leading, spacing: 2) {
                    Text(isNew ? model.text("New Server") : model.text("Edit Server")).font(.title3.bold())
                    Text(model.text("SSH connection")).font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                Button { profile.isFavorite.toggle() } label: {
                    Image(systemName: profile.isFavorite ? "star.fill" : "star")
                        .font(.title3)
                        .foregroundStyle(profile.isFavorite ? Color.accentColor : Color.secondary)
                        .frame(width: 30, height: 30)
                }
                .buttonStyle(.borderless)
                .help(profile.isFavorite ? model.text("Remove from favorites") : model.text("Add to favorites"))
                .accessibilityLabel(profile.isFavorite ? model.text("Remove from favorites") : model.text("Add to favorites"))
            }.padding(.horizontal, 16).padding(.vertical, 12)
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    VStack(alignment: .leading, spacing: 8) {
                        Text(model.text("CONNECTION"))
                            .font(.system(size: 10, weight: .semibold)).foregroundStyle(.secondary)
                            .accessibilityAddTraits(.isHeader)
                        connectionFields
                    }
                    Divider()
                    VStack(alignment: .leading, spacing: 8) {
                        Text(model.text("AUTHENTICATION"))
                            .font(.system(size: 10, weight: .semibold)).foregroundStyle(.secondary)
                            .accessibilityAddTraits(.isHeader)
                        authenticationFields
                    }
                    if let source = profile.sshConfigPath {
                        Divider()
                        VStack(alignment: .leading, spacing: 6) {
                            Text(model.text("SSH CONFIGURATION"))
                                .font(.system(size: 10, weight: .semibold)).foregroundStyle(.secondary)
                                .accessibilityAddTraits(.isHeader)
                            Text(source).font(.caption.monospaced()).textSelection(.enabled)
                            Text(model.text("Unset fields inherit this file. SSH configuration may run local commands; use only files you trust."))
                                .font(.caption).foregroundStyle(.secondary)
                            Button(model.text("Stop inheriting this configuration"), role: .destructive) { profile.sshConfigPath = nil }
                                .controlSize(.small)
                        }
                    }
                    DisclosureGroup(model.text("Notes"), isExpanded: $notesExpanded) {
                        TextField(model.text("Notes"), text: $profile.notes, prompt: Text(model.text("Add a note…")), axis: .vertical)
                            .lineLimit(2...4).padding(.top, 6)
                    }.font(.callout)
                }
                .textFieldStyle(.roundedBorder)
                .padding(16)
            }.frame(minHeight: 0, maxHeight: .infinity)
            if let problem {
                Label(model.describe(problem), systemImage: "exclamationmark.circle")
                    .foregroundStyle(.red).font(.callout)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 16).padding(.bottom, 12)
            }
            Divider()
            HStack {
                Button(model.text("Cancel"), action: onClose).keyboardShortcut(.cancelAction)
                Spacer()
                Button(model.text("Save Server"), action: save).buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction)
            }.padding(.horizontal, 16).padding(.vertical, 12)
        }
        .onDisappear {
            password = ""
            privateKey = ""
        }
    }

    private var connectionFields: some View {
        VStack(alignment: .leading, spacing: 10) {
            VStack(alignment: .leading, spacing: 4) {
                Text(model.text("Name")).font(.caption).foregroundStyle(.secondary)
                TextField(model.text("Name"), text: $profile.name, prompt: Text(model.text("Production server")))
            }
            HStack(alignment: .top, spacing: 10) {
                VStack(alignment: .leading, spacing: 4) {
                    Text(model.text("Host or SSH alias")).font(.caption).foregroundStyle(.secondary)
                    TextField(model.text("Host or SSH alias"), text: $profile.host, prompt: Text(model.text("server.example.com")))
                }
                VStack(alignment: .leading, spacing: 4) {
                    Text(model.text("Port")).font(.caption).foregroundStyle(.secondary)
                    TextField(model.text("Port"), text: $portText, prompt: Text(model.text("22")))
                        .help(model.text("Leave blank to use SSH config or port 22."))
                }.frame(width: 72)
            }
            HStack(alignment: .top, spacing: 10) {
                VStack(alignment: .leading, spacing: 4) {
                    Text(model.text("Username")).font(.caption).foregroundStyle(.secondary)
                    TextField(model.text("Username"), text: $profile.user, prompt: Text(model.text("deploy")))
                        .help(model.text("Leave blank to use the username from SSH config or your local account."))
                }.frame(maxWidth: .infinity)
                VStack(alignment: .leading, spacing: 4) {
                    Text(model.text("Group")).font(.caption).foregroundStyle(.secondary)
                    EditableGroupComboBox(text: $profile.group, suggestions: model.groupSuggestions,
                                          placeholder: model.text("Select or type…"), accessibilityLabel: model.text("Group"))
                        .frame(height: 22)
                }.frame(maxWidth: .infinity)
            }
        }
    }

    private var authenticationFields: some View {
        VStack(alignment: .leading, spacing: 10) {
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    Text(model.text("Private key")).font(.caption).foregroundStyle(.secondary)
                    Spacer()
                    Button(isEnteringPrivateKey ? model.text("Use file path") : model.text("Enter / paste key")) {
                        privateKey = ""
                        isEnteringPrivateKey.toggle()
                    }.buttonStyle(.link).font(.caption)
                }
                if isEnteringPrivateKey {
                    PrivateKeyTextEditor(text: $privateKey, accessibilityLabel: model.text("Private key text")).frame(height: 112)
                    HStack {
                        Text(model.text("Saved privately only on Save.")).font(.caption).foregroundStyle(.secondary)
                        Spacer()
                        Button(model.text("Choose file…"), action: chooseKey).controlSize(.small)
                    }
                } else {
                    HStack(spacing: 6) {
                        TextField(model.text("Private key file"), text: $profile.identityFile, prompt: Text(model.text("~/.ssh/id_ed25519")))
                        Button(action: chooseKey) { Image(systemName: "folder").frame(width: 18, height: 18) }
                            .help(model.text("Choose private key file")).accessibilityLabel(model.text("Choose private key file"))
                        if !profile.identityFile.isEmpty {
                            Button { profile.identityFile = "" } label: { Image(systemName: "xmark.circle.fill") }
                                .buttonStyle(.plain).foregroundStyle(.secondary)
                                .help(model.text("Remove private key")).accessibilityLabel(model.text("Remove private key"))
                        }
                    }
                }
                Text(model.text("Optional. Encrypted keys are unlocked when connecting."))
                    .font(.caption).foregroundStyle(.secondary)
            }
            Divider()
            VStack(alignment: .leading, spacing: 4) {
                Text(model.text("Server password")).font(.caption).foregroundStyle(.secondary)
                PasswordField(title: model.text("Server password"), text: $password, localizer: model.localizer,
                              prompt: keepSavedPassword ? model.text("Leave blank to keep password") : model.text("Enter password"))
                    .help(keepSavedPassword
                          ? model.text("Leave blank to keep password")
                          : model.text("Leave blank to enter your password when SSH asks. Entered passwords are saved in Keychain."))
                if originallySavedPassword && password.isEmpty {
                    HStack {
                        Text(keepSavedPassword ? model.text("Saved in Keychain.") : model.text("Removed on Save."))
                            .font(.caption).foregroundStyle(.secondary)
                        Spacer()
                        Button(keepSavedPassword ? model.text("Remove saved password") : model.text("Undo removal")) {
                            keepSavedPassword.toggle()
                        }.buttonStyle(.link).font(.caption)
                    }
                } else {
                    Text(model.text("Optional. Entered passwords are saved in Keychain."))
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
        }
    }

    private func chooseKey() {
        let panel = NSOpenPanel()
        panel.title = model.text("Choose an SSH private key")
        panel.prompt = model.text("Choose")
        panel.showsHiddenFiles = true
        panel.directoryURL = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".ssh")
        panel.canChooseDirectories = false
        if model.withNativeInteraction({ panel.runModal() }) == .OK, let url = panel.url {
            profile.identityFile = url.path
            privateKey = ""
            isEnteringPrivateKey = false
        }
    }

    private func save() {
        // End native field editing before reading the bound draft, including typed group names.
        NSApp.keyWindow?.makeFirstResponder(nil)
        do {
            var saved = profile
            let port = portText.trimmingCharacters(in: .whitespacesAndNewlines)
            if port.isEmpty { saved.port = nil }
            else if let number = Int(port) { saved.port = number }
            else { throw ShuttleError.invalidProfile("Port must be a number between 1 and 65535.") }
            saved.identityFile = saved.identityFile.trimmingCharacters(in: .whitespacesAndNewlines)
            if !saved.identityFile.isEmpty { saved.identity = .privateKey }
            else if saved.identity == .privateKey || isNew {
                saved.identity = .automatic
            }
            saved.passwordMode = !password.isEmpty || keepSavedPassword ? .keychain : .askWhenNeeded
            try model.save(saved, password: password.isEmpty ? nil : password,
                           privateKey: privateKey.isEmpty ? nil : privateKey)
            password = ""
            privateKey = ""
            onClose()
        } catch { problem = error }
    }
}

private struct PrivateKeyTextEditor: NSViewRepresentable {
    @Binding var text: String
    let accessibilityLabel: String

    func makeCoordinator() -> Coordinator { Coordinator(self) }

    func makeNSView(context: Context) -> NSScrollView {
        let scroll = NSScrollView()
        scroll.borderType = .bezelBorder
        scroll.hasVerticalScroller = true
        scroll.autohidesScrollers = true

        let editor = NSTextView()
        editor.isRichText = false
        editor.importsGraphics = false
        editor.allowsUndo = true
        editor.isAutomaticQuoteSubstitutionEnabled = false
        editor.isAutomaticDashSubstitutionEnabled = false
        editor.isAutomaticTextReplacementEnabled = false
        editor.isAutomaticSpellingCorrectionEnabled = false
        editor.isAutomaticTextCompletionEnabled = false
        editor.isAutomaticLinkDetectionEnabled = false
        editor.isAutomaticDataDetectionEnabled = false
        editor.isContinuousSpellCheckingEnabled = false
        editor.isGrammarCheckingEnabled = false
        editor.smartInsertDeleteEnabled = false
        editor.font = .monospacedSystemFont(ofSize: 11, weight: .regular)
        editor.textContainerInset = NSSize(width: 4, height: 4)
        editor.isVerticallyResizable = true
        editor.isHorizontallyResizable = false
        editor.autoresizingMask = [.width]
        editor.textContainer?.widthTracksTextView = true
        editor.setAccessibilityLabel(accessibilityLabel)
        editor.string = text
        editor.delegate = context.coordinator
        scroll.documentView = editor
        return scroll
    }

    func updateNSView(_ scroll: NSScrollView, context: Context) {
        context.coordinator.parent = self
        guard let editor = scroll.documentView as? NSTextView else { return }
        editor.setAccessibilityLabel(accessibilityLabel)
        // Reassigning matching text resets native selection and undo.
        if editor.string != text { editor.string = text }
    }

    final class Coordinator: NSObject, NSTextViewDelegate {
        var parent: PrivateKeyTextEditor

        init(_ parent: PrivateKeyTextEditor) { self.parent = parent }

        func textDidChange(_ notification: Notification) {
            guard let editor = notification.object as? NSTextView else { return }
            parent.text = editor.string
        }
    }
}


private struct EditableGroupComboBox: NSViewRepresentable {
    @Binding var text: String
    let suggestions: [String]
    let placeholder: String
    let accessibilityLabel: String

    func makeCoordinator() -> Coordinator { Coordinator(self) }

    func makeNSView(context: Context) -> NSComboBox {
        let combo = NSComboBox()
        combo.isEditable = true
        combo.completes = false
        combo.hasVerticalScroller = true
        combo.numberOfVisibleItems = 8
        combo.placeholderString = placeholder
        combo.setAccessibilityLabel(accessibilityLabel)
        combo.setContentHuggingPriority(.defaultLow, for: .horizontal)
        combo.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        combo.addItems(withObjectValues: suggestions)
        combo.stringValue = text
        combo.delegate = context.coordinator
        return combo
    }

    func updateNSView(_ combo: NSComboBox, context: Context) {
        let suggestionsChanged = context.coordinator.parent.suggestions != suggestions
        context.coordinator.parent = self
        combo.placeholderString = placeholder
        combo.setAccessibilityLabel(accessibilityLabel)
        if suggestionsChanged {
            combo.removeAllItems()
            combo.addItems(withObjectValues: suggestions)
        }
        if (combo.currentEditor()?.string ?? combo.stringValue) != text {
            combo.stringValue = text
        }
    }

    final class Coordinator: NSObject, NSComboBoxDelegate {
        var parent: EditableGroupComboBox

        init(_ parent: EditableGroupComboBox) { self.parent = parent }

        func controlTextDidChange(_ notification: Notification) {
            guard let combo = notification.object as? NSComboBox else { return }
            parent.text = combo.stringValue
        }

        func controlTextDidEndEditing(_ notification: Notification) {
            guard let combo = notification.object as? NSComboBox else { return }
            parent.text = combo.stringValue
        }

        func comboBoxSelectionDidChange(_ notification: Notification) {
            guard let combo = notification.object as? NSComboBox,
                  let selection = combo.objectValueOfSelectedItem as? String else { return }
            combo.stringValue = selection
            parent.text = selection
        }
    }
}
