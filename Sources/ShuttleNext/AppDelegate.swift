import AppKit
import Combine
import Carbon
import SwiftUI
import ShuttleCore

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate, NSPopoverDelegate {
    let model: AppModel
    private var statusItem: NSStatusItem?
    private var popover: NSPopover?
    private var shortcut: GlobalShortcut?
    private var localizationObserver: AnyCancellable?

    override init() {
        model = AppModel()
        super.init()
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        model.presentPopover = { [weak self] in self?.showPopover() }
        model.dismissPopover = { [weak self] in self?.popover?.performClose(nil) }
        model.nativeInteractionEnded = { [weak self] in self?.dismissInactivePopover() }
        model.settingsChanged = { [weak self] settings in try self?.configureShortcut(settings) }
        do { try configureShortcut(model.settings) }
        catch { model.errorMessage = model.describe(error) }

        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        if let button = item.button {
            button.image = ShuttleIcon.statusImage()
            button.target = self
            button.action = #selector(togglePopover)
        }
        statusItem = item
        localizationObserver = model.$document.map(\.settings.language).removeDuplicates().sink { [weak self] _ in
            guard let self else { return }
            installEditingMenu()
            statusItem?.button?.toolTip = model.text("ShuttleNext — SSH connections")
            statusItem?.button?.setAccessibilityLabel(model.text("ShuttleNext — SSH connections"))
            statusItem?.button?.image?.accessibilityDescription = model.text("ShuttleNext — SSH connections")
        }
        if model.profiles.isEmpty {
            DispatchQueue.main.async { [weak self] in self?.showPopover() }
        }
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        showPopover()
        return true
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }

    func applicationDidResignActive(_ notification: Notification) {
        dismissInactivePopover()
    }

    private func dismissInactivePopover() {
        guard !NSApp.isActive, model.canDismissPopover else { return }
        popover?.performClose(nil)
    }

    func popoverShouldClose(_ popover: NSPopover) -> Bool {
        model.canDismissPopover
    }

    func applicationWillTerminate(_ notification: Notification) {
        shortcut?.unregister()
        if let statusItem { NSStatusBar.system.removeStatusItem(statusItem) }
    }

    @objc func togglePopover() {
        if popover?.isShown == true { popover?.performClose(nil) }
        else { showPopover() }
    }

    func showPopover() {
        guard let button = statusItem?.button else { return }
        if popover?.isShown == true {
            popover?.contentViewController?.view.window?.makeKey()
            return
        }
        let panel = NSPopover()
        panel.animates = false
        panel.behavior = .transient
        panel.delegate = self
        let height = min(600, (button.window?.screen?.visibleFrame.height ?? 650) - 40)
        panel.contentViewController = NSHostingController(rootView:
            MenuBarView(model: model, maximumHeight: height) { [weak panel] height in
                panel?.contentSize = NSSize(width: 460, height: height)
            }
            .frame(width: 460)
        )
        popover = panel
        NSApp.activate(ignoringOtherApps: true)
        panel.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
        panel.contentViewController?.view.window?.makeKey()
    }

    func popoverDidClose(_ notification: Notification) {
        guard let closed = notification.object as? NSPopover, closed === popover else { return }
        closed.contentViewController = nil
        popover = nil
    }

    private func installEditingMenu() {
        let main = NSMenu()
        let edit = NSMenu(title: model.text("Edit"))
        let item = NSMenuItem(title: model.text("Edit"), action: nil, keyEquivalent: "")
        item.submenu = edit
        main.addItem(item)

        let undo = NSMenuItem(title: model.text("Undo"), action: Selector(("undo:")), keyEquivalent: "z")
        let redo = NSMenuItem(title: model.text("Redo"), action: Selector(("redo:")), keyEquivalent: "Z")
        edit.addItem(undo)
        edit.addItem(redo)
        edit.addItem(.separator())
        edit.addItem(withTitle: model.text("Cut"), action: #selector(NSText.cut(_:)), keyEquivalent: "x")
        edit.addItem(withTitle: model.text("Copy"), action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        edit.addItem(withTitle: model.text("Paste"), action: #selector(NSText.paste(_:)), keyEquivalent: "v")
        edit.addItem(.separator())
        edit.addItem(withTitle: model.text("Select All"), action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
        // Nil targets preserve the native responder chain and secure-field validation.
        NSApp.mainMenu = main
    }

    private func configureShortcut(_ settings: AppSettings) throws {
        if !settings.globalShortcutEnabled { shortcut?.unregister(); shortcut = nil; return }
        guard shortcut == nil else { return }
        let shortcut = GlobalShortcut { [weak self] in self?.togglePopover() }
        try shortcut.register()
        self.shortcut = shortcut
    }
}

@MainActor
final class GlobalShortcut {
    private var hotKey: EventHotKeyRef?
    private var handler: EventHandlerRef?
    private let action: () -> Void
    init(action: @escaping () -> Void) { self.action = action }

    func register() throws {
        var event = EventTypeSpec(eventClass: OSType(kEventClassKeyboard), eventKind: UInt32(kEventHotKeyPressed))
        let context = Unmanaged.passUnretained(self).toOpaque()
        let handlerStatus = InstallEventHandler(GetApplicationEventTarget(), { _, event, context in
            guard let context, let event else { return OSStatus(eventNotHandledErr) }
            var identifier = EventHotKeyID()
            guard GetEventParameter(event, EventParamName(kEventParamDirectObject), EventParamType(typeEventHotKeyID), nil, MemoryLayout<EventHotKeyID>.size, nil, &identifier) == noErr,
                  identifier.signature == 0x53484E58, identifier.id == 1 else { return OSStatus(eventNotHandledErr) }
            let owner = Unmanaged<GlobalShortcut>.fromOpaque(context).takeUnretainedValue()
            MainActor.assumeIsolated { owner.action() }
            return noErr
        }, 1, &event, context, &handler)
        guard handlerStatus == noErr else { throw ShuttleError.connection("The global shortcut could not be registered (\(handlerStatus)).") }
        let result = RegisterEventHotKey(UInt32(kVK_ANSI_K), UInt32(cmdKey | shiftKey), EventHotKeyID(signature: 0x53484E58, id: 1), GetApplicationEventTarget(), UInt32(kEventHotKeyExclusive), &hotKey)
        if result != noErr {
            if let handler { RemoveEventHandler(handler) }; handler = nil
            throw ShuttleError.connection("⌘⇧K is unavailable, possibly because another app uses it. The global shortcut was not activated.")
        }
    }

    func unregister() {
        if let hotKey { UnregisterEventHotKey(hotKey) }; hotKey = nil
        if let handler { RemoveEventHandler(handler) }; handler = nil
    }
}
