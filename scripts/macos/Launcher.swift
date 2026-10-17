import AppKit

final class SlurpDelegate: NSObject, NSApplicationDelegate {
    private var backend: Process?
    private var statusItem: NSStatusItem?
    private var log: FileHandle?
    private var logPath = ""
    private var output = ""
    private var webURL: URL?
    private var quitting = false

    func applicationDidFinishLaunching(_ notification: Notification) {
        if let identifier = Bundle.main.bundleIdentifier,
           let other = NSRunningApplication.runningApplications(withBundleIdentifier: identifier)
            .first(where: { $0.processIdentifier != ProcessInfo.processInfo.processIdentifier }) {
            other.activate(options: [.activateIgnoringOtherApps])
            NSApp.terminate(nil)
            return
        }
        let menu = NSMenu()
        let open = menu.addItem(withTitle: "Open Slurp", action: #selector(openWeb), keyEquivalent: "o")
        open.target = self
        menu.addItem(.separator())
        let quit = menu.addItem(withTitle: "Quit Slurp", action: #selector(quitApp), keyEquivalent: "q")
        quit.target = self
        let appMenu = NSMenu()
        let root = NSMenuItem()
        root.submenu = menu
        appMenu.addItem(root)
        NSApp.mainMenu = appMenu
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        statusItem?.button?.image = NSImage(systemSymbolName: "waveform.path.ecg", accessibilityDescription: "Slurp")
        statusItem?.menu = menu.copy() as? NSMenu
        statusItem?.button?.toolTip = "Slurp — Sip traffic"
        do {
            let directory = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Logs/Slurp", isDirectory: true)
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            let file = directory.appendingPathComponent("slurp.log")
            logPath = file.path
            if let size = try? file.resourceValues(forKeys: [.fileSizeKey]).fileSize, size > 5_000_000 {
                let previous = directory.appendingPathComponent("slurp.previous.log")
                if FileManager.default.fileExists(atPath: previous.path) { try FileManager.default.removeItem(at: previous) }
                try FileManager.default.moveItem(at: file, to: previous)
            }
            if !FileManager.default.fileExists(atPath: file.path) {
                FileManager.default.createFile(atPath: file.path, contents: nil, attributes: [.posixPermissions: 0o600])
            }
            log = try FileHandle(forWritingTo: file)
            log?.seekToEndOfFile()
            guard let resource = Bundle.main.resourceURL else { throw CocoaError(.fileNoSuchFile) }
            let process = Process()
            process.executableURL = resource.appendingPathComponent("slurp")
            process.arguments = ["--no-open"]
            process.currentDirectoryURL = FileManager.default.homeDirectoryForCurrentUser
            let pipe = Pipe()
            process.standardOutput = pipe
            process.standardError = pipe
            process.standardInput = FileHandle.nullDevice
            pipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
                let data = handle.availableData
                if data.isEmpty { handle.readabilityHandler = nil; return }
                DispatchQueue.main.async { self?.received(data) }
            }
            process.terminationHandler = { [weak self] process in
                DispatchQueue.main.async {
                    guard let self = self else { return }
                    if self.quitting { NSApp.reply(toApplicationShouldTerminate: true) }
                    else {
                        self.backend = nil
                        self.showError("Slurp stopped (exit \(process.terminationStatus)). Another Slurp instance may already be using the UI or proxy port.\n\nLog: \(self.logPath)")
                        NSApp.terminate(nil)
                    }
                }
            }
            backend = process
            try process.run()
        } catch {
            backend = nil
            showError("Could not start Slurp: \(error.localizedDescription)")
            NSApp.terminate(nil)
        }
    }

    private func received(_ data: Data) {
        log?.write(data)
        output += String(decoding: data, as: UTF8.self)
        if webURL == nil, let expression = try? NSRegularExpression(pattern: #"UI:\s+(http://[^\s]+)"#),
           let match = expression.firstMatch(in: output, range: NSRange(output.startIndex..., in: output)),
           let range = Range(match.range(at: 1), in: output), let url = URL(string: String(output[range])) {
            webURL = url
            if ProcessInfo.processInfo.environment["SLURP_APP_NO_OPEN"] != "1" { NSWorkspace.shared.open(url) }
        }
        if output.count > 64_000 { output = String(output.suffix(32_000)) }
    }
    private func showError(_ message: String) {
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = "Slurp"
        alert.informativeText = message
        alert.alertStyle = .warning
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }
    @objc private func openWeb() { if let url = webURL { NSWorkspace.shared.open(url) } }
    @objc private func quitApp() { NSApp.terminate(nil) }
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        openWeb()
        return false
    }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard let process = backend, process.isRunning else { return .terminateNow }
        quitting = true
        process.interrupt()
        DispatchQueue.main.asyncAfter(deadline: .now() + 5) {
            if process.isRunning { process.terminate() }
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 8) {
            if process.isRunning { kill(process.processIdentifier, SIGKILL) }
        }
        return .terminateLater
    }
    func applicationWillTerminate(_ notification: Notification) {
        if let process = backend, process.isRunning { process.interrupt() }
        try? log?.close()
    }
}

let app = NSApplication.shared
let delegate = SlurpDelegate()
app.setActivationPolicy(.regular)
app.delegate = delegate
app.run()
