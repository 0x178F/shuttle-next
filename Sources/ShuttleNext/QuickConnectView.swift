import SwiftUI
import ShuttleCore

struct QuickConnectView: View {
    @ObservedObject var model: AppModel
    let add: () -> Void
    let edit: (ServerProfile) -> Void
    let remove: (ServerProfile) -> Void
    let importFile: () -> Void
    let exportFile: () -> Void
    let settings: () -> Void
    @State private var query = ""
    @State private var highlightedID: UUID?
    @State private var copiedID: UUID?
    @State private var keyboardScrollRequest = 0
    @FocusState private var searchFocused: Bool
    @FocusState private var focusedEditID: UUID?
    @FocusState private var focusedCopyID: UUID?

    private static let unquotedShellCharacters = CharacterSet(charactersIn:
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_@%+=:,./-")

    private var matches: [ServerProfile] {
        let ungrouped = model.text("UNGROUPED")
        return model.profiles.filter {
            query.isEmpty || $0.name.localizedStandardContains(query) ||
            $0.host.localizedStandardContains(query) || $0.user.localizedStandardContains(query) ||
            ($0.group.isEmpty ? ungrouped : $0.group).localizedStandardContains(query)
        }.sorted {
            if $0.isFavorite != $1.isFavorite { return $0.isFavorite }
            if $0.group.isEmpty != $1.group.isEmpty { return !$0.group.isEmpty }
            let groupOrder = $0.group.localizedStandardCompare($1.group)
            if groupOrder != .orderedSame { return groupOrder == .orderedAscending }
            return $0.name.localizedStandardCompare($1.name) == .orderedAscending
        }
    }

    var body: some View {
        let profiles = matches
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                TextField(model.text("Connect to a server…"), text: $query)
                    .textFieldStyle(.plain).focused($searchFocused)
                    .onSubmit { connectHighlighted() }
                    .onKeyPress(keys: [.upArrow, .downArrow]) { press in
                        moveSelection(press.key == .downArrow ? 1 : -1)
                        keyboardScrollRequest &+= 1
                        return .handled
                    }
                if !query.isEmpty {
                    Button { query = "" } label: { Image(systemName: "xmark.circle.fill").foregroundStyle(.secondary) }
                        .buttonStyle(.plain).accessibilityLabel(model.text("Clear search"))
                }
            }.padding(.horizontal, 16).padding(.vertical, 12).fixedSize(horizontal: false, vertical: true)
            .font(.callout)
            Divider()
            if let storageProblem = model.storageProblem {
                Label(storageProblem, systemImage: "exclamationmark.triangle")
                    .font(.callout).foregroundStyle(.orange).padding(18)
                Button(model.text("Recover Library"), action: settings).padding(.bottom, 18)
                Spacer()
            } else if model.profiles.isEmpty {
                ScrollView {
                    VStack(spacing: 12) {
                        Image(systemName: "server.rack").font(.system(size: 32)).foregroundStyle(.secondary)
                        Text(model.text("A shorter path to your servers")).font(.headline)
                        Text(model.text("Add a server or import existing connections.")).foregroundStyle(.secondary)
                        Button(model.text("Add Server"), action: add).buttonStyle(.borderedProminent)
                        Button(model.text("Import…"), action: importFile)
                            .accessibilityLabel(model.text("Import connections"))
                    }
                    .frame(maxWidth: .infinity).padding(.horizontal, 16).padding(.vertical, 24)
                }.frame(minHeight: 0, maxHeight: .infinity)
            } else if profiles.isEmpty {
                ScrollView {
                    VStack(spacing: 8) {
                        Label(model.text("No matching servers"), systemImage: "magnifyingglass").font(.headline)
                        Text(model.text("Try a different name, host, or group.")).font(.caption).foregroundStyle(.secondary)
                    }.frame(maxWidth: .infinity).padding(24)
                }.frame(minHeight: 0, maxHeight: .infinity)
            } else {
                ScrollViewReader { reader in
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 2) {
                            ForEach(Array(profiles.enumerated()), id: \.element.id) { index, profile in
                                if startsSection(at: index, in: profiles) {
                                    let title = profile.isFavorite ? model.text("FAVORITES") : (profile.group.isEmpty ? model.text("UNGROUPED") : profile.group)
                                    Text(title)
                                        .font(.system(size: 10, weight: .medium)).foregroundStyle(.secondary)
                                        .tracking(0.35).textCase(.uppercase)
                                        .accessibilityAddTraits(.isHeader)
                                        .lineLimit(1).truncationMode(.middle).help(title)
                                        .padding(.horizontal, 8)
                                        .padding(.top, index == 0 ? 6 : 12).padding(.bottom, 3)
                                }
                                let showsActions = highlightedID == profile.id || focusedEditID == profile.id ||
                                    focusedCopyID == profile.id || copiedID == profile.id
                                HStack(spacing: 8) {
                                    Button { model.toggleFavorite(profile) } label: {
                                        Image(systemName: profile.isFavorite ? "star.fill" : "star")
                                            .font(.system(size: 12))
                                            .foregroundStyle(profile.isFavorite ? Color.orange : Color.secondary)
                                            .frame(width: 28, height: 44)
                                            .contentShape(Rectangle())
                                    }
                                    .help(profile.isFavorite ? model.text("Remove from favorites") : model.text("Add to favorites"))
                                    .accessibilityLabel(profile.isFavorite ? model.text("Remove favorite \(profile.name)") : model.text("Add favorite \(profile.name)"))
                                    .accessibilityValue(profile.isFavorite ? model.text("Favorite") : model.text("Not favorite"))
                                    Button { model.connect(profile) } label: {
                                        VStack(alignment: .leading, spacing: 2) {
                                            Text(profile.name).font(.callout.weight(.medium)).lineLimit(1)
                                            Text(profile.destination).font(.caption).foregroundStyle(.secondary)
                                                .lineLimit(1).truncationMode(.middle)
                                        }
                                        .padding(.vertical, 6)
                                        .frame(maxWidth: .infinity, minHeight: 44, alignment: .leading)
                                        .contentShape(Rectangle())
                                    }
                                    .disabled(model.isOpeningConnection)
                                    .accessibilityLabel(model.text("Connect to \(profile.name), \(profile.destination)"))
                                    Button { copyCommand(for: profile) } label: {
                                        Image(systemName: copiedID == profile.id ? "checkmark" : "doc.on.doc")
                                            .frame(width: 28, height: 44)
                                            .contentShape(Rectangle())
                                    }
                                    .foregroundStyle(.secondary)
                                    .focused($focusedCopyID, equals: profile.id)
                                    .opacity(showsActions ? 1 : 0)
                                    .help(copiedID == profile.id ? model.text("SSH command copied") : model.text("Copy SSH command"))
                                    .accessibilityLabel(model.text("Copy SSH command for \(profile.name)"))
                                    .accessibilityValue(copiedID == profile.id ? model.text("SSH command copied") : "")
                                    Button { edit(profile) } label: { Image(systemName: "pencil").frame(width: 28, height: 44) }
                                        .foregroundStyle(.secondary)
                                        .focused($focusedEditID, equals: profile.id)
                                        .opacity(showsActions ? 1 : 0)
                                        .help(model.text("Edit \(profile.name)")).accessibilityLabel(model.text("Edit \(profile.name)"))
                                }
                                .padding(.horizontal, 4).frame(minHeight: 44)
                                .buttonStyle(.plain).id(profile.id)
                                .background(highlightedID == profile.id ? Color.accentColor.opacity(0.10) : Color.clear, in: RoundedRectangle(cornerRadius: 6))
                                .onHover { if $0 { highlightedID = profile.id } }
                                .contextMenu {
                                    Button(model.text("Connect")) { model.connect(profile) }
                                    Button(model.text("Edit")) { edit(profile) }
                                    Button(profile.isFavorite ? model.text("Remove Favorite") : model.text("Add Favorite")) { model.toggleFavorite(profile) }
                                    Button(model.text("Duplicate")) { edit(model.duplicate(profile)) }
                                    Divider()
                                    Button(model.text("Remove Server…"), role: .destructive) { remove(profile) }
                                }
                            }
                        }.padding(8)
                    }
                    .frame(maxHeight: .infinity)
                    .onChange(of: query) { _, _ in
                        if let id = profiles.first?.id { reader.scrollTo(id, anchor: .top) }
                    }
                    .onChange(of: keyboardScrollRequest) { _, _ in
                        if let id = highlightedID { reader.scrollTo(id, anchor: .center) }
                    }
                }
            }
            Divider()
            HStack(spacing: 14) {
                Button(action: add) { Label(model.text("Add Server"), systemImage: "plus") }
                    .keyboardShortcut("n").disabled(model.storageProblem != nil)
                Spacer()
                Menu {
                    if let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String {
                        Text(verbatim: "ShuttleNext \(version)")
                    } else {
                        Text(verbatim: "ShuttleNext")
                    }
                    Divider()
                    Button(action: settings) { Label(model.text("Settings"), systemImage: "gearshape") }
                    Divider()
                    Button(action: importFile) { Label(model.text("Import…"), systemImage: "square.and.arrow.down") }
                        .disabled(model.storageProblem != nil)
                    Button(action: exportFile) { Label(model.text("Export…"), systemImage: "square.and.arrow.up") }
                        .disabled(model.storageProblem != nil || model.profiles.isEmpty)
                    Divider()
                    Button(model.text("Quit ShuttleNext")) { NSApplication.shared.terminate(nil) }.keyboardShortcut("q")
                } label: { Image(systemName: "ellipsis.circle") }
                    .menuStyle(.borderlessButton).menuIndicator(.hidden).fixedSize()
                    .help(model.text("Application menu")).accessibilityLabel(model.text("Application menu"))
            }.buttonStyle(.plain).foregroundStyle(.secondary).font(.callout)
                .padding(.horizontal, 16).padding(.vertical, 12)
                .fixedSize(horizontal: false, vertical: true)
        }
        .onAppear { highlightedID = profiles.first?.id; searchFocused = true }
        .onChange(of: query) { _, _ in highlightedID = profiles.first?.id }
        .task(id: copiedID) {
            guard copiedID != nil else { return }
            do { try await Task.sleep(for: .seconds(1.5)) }
            catch { return }
            copiedID = nil
        }
        .onExitCommand { model.dismissPopover?() }
    }

    private func copyCommand(for profile: ServerProfile) {
        do {
            let profile = try profile.validated()
            var arguments: [String] = []
            if let path = profile.sshConfigPath { arguments += ["-F", path] }
            if let port = profile.port { arguments += ["-p", String(port)] }
            if profile.identity == .privateKey { arguments += ["-i", profile.identityFile] }
            arguments.append(profile.destination)
            let command = "ssh " + arguments.map { argument in
                argument.unicodeScalars.allSatisfy(Self.unquotedShellCharacters.contains)
                    ? argument : SSHCommand.shellQuote(argument)
            }.joined(separator: " ")
            let pasteboard = NSPasteboard.general
            pasteboard.clearContents()
            guard pasteboard.setString(command, forType: .string) else {
                copiedID = nil
                model.errorMessage = model.text("The SSH command could not be copied.")
                return
            }
            copiedID = profile.id
        } catch {
            copiedID = nil
            model.errorMessage = model.describe(error)
        }
    }

    private func startsSection(at index: Int, in profiles: [ServerProfile]) -> Bool {
        index == 0 || profiles[index].isFavorite != profiles[index - 1].isFavorite || (!profiles[index].isFavorite && profiles[index].group != profiles[index - 1].group)
    }
    // Search input can change before SwiftUI rerenders; key handlers need current matches.
    private func moveSelection(_ delta: Int) {
        let profiles = matches
        guard !profiles.isEmpty else { return }
        let current = highlightedID.flatMap { id in profiles.firstIndex { $0.id == id } } ?? -1
        highlightedID = profiles[min(max(current + delta, 0), profiles.count - 1)].id
    }
    private func connectHighlighted() {
        let profiles = matches
        guard let profile = profiles.first(where: { $0.id == highlightedID }) ?? profiles.first else { return }
        model.connect(profile)
    }
}
