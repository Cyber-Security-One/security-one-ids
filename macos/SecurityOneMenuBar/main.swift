// Security One Agent — macOS menu bar console.
//
// Shows what the agent on this machine currently knows about itself: the
// endpoint sensor, the behaviour correlator, Suricata, ClamAV and the Hub
// connection, plus the one number nobody can guess — how far back the spool
// actually reaches, per class of event.
//
// It reads `php artisan ids:status --json`, which is the same snapshot the CLI
// renders. That is deliberate: a console with its own idea of what "healthy"
// means is a second implementation that drifts from the first, and the drift
// is invisible until the day they disagree about something that matters.
//
// Three display rules, which are the same ones the snapshot itself follows:
//
//   * Unknown is never painted green. If the agent could not determine
//     something — usually because this app runs unprivileged and the Hub
//     credentials are root-only — it says so. A console that shows "fine" for
//     "could not tell" is worse than one that shows nothing.
//   * Warming is not a fault. The correlator is silent by design for its first
//     fortnight, and a red dot for two weeks trains people to ignore red.
//   * Staleness is data. If the snapshot cannot be refreshed, the age of the
//     last one is shown rather than the last one being presented as current.

import AppKit
import Foundation

// MARK: - Model

enum Health: String {
    case ok, warming, degraded, down, disabled, unsupported, unknown

    /// Colour carries meaning, so it is assigned from state and nowhere else.
    var color: NSColor {
        switch self {
        case .ok:                     return .systemGreen
        case .warming:                return .systemTeal
        case .degraded, .unknown:     return .systemYellow
        case .down:                   return .systemRed
        case .disabled, .unsupported: return .tertiaryLabelColor
        }
    }

    var symbol: String {
        switch self {
        case .disabled, .unsupported: return "○"
        case .unknown:                return "?"
        default:                      return "●"
        }
    }

    init(_ raw: String?) {
        self = Health(rawValue: raw ?? "unknown") ?? .unknown
    }
}

struct Snapshot {
    var overall: Health = .unknown
    var reasons: [String] = []
    var hostName = "—"
    var hostOS = ""
    var rows: [Row] = []
    var retention: [(String, Int, Double?)] = []
    var generatedAt: Date?
    /// Set when the snapshot could not be produced at all.
    var failure: String?

    struct Row {
        let title: String
        let detail: String
        let health: Health
    }
}

// MARK: - Reading the agent

enum AgentReader {
    /// Where the agent lives. The installer puts it here on both platforms.
    static let installPath = "/opt/security-one-ids"

    /// PHP is wherever this machine keeps it. Homebrew on Apple Silicon uses
    /// /opt/homebrew, Intel uses /usr/local, and a system PHP may be neither —
    /// so the candidates are tried in order rather than assumed.
    static let phpCandidates = [
        "/opt/homebrew/bin/php",
        "/usr/local/bin/php",
        "/usr/bin/php",
    ]

    static func resolvePHP() -> String? {
        phpCandidates.first { FileManager.default.isExecutableFile(atPath: $0) }
    }

    /// How long the agent gets to answer.
    ///
    /// It shells out to osqueryd, systemctl and friends, each with its own
    /// timeout, so a slow answer is normal and an infinite one is possible.
    /// Without a bound here the reader blocks forever on a pipe that will
    /// never close: the console freezes on stale data, or — worse, and this is
    /// how it was found — a diagnostic that had already computed its answer
    /// sits waiting to print it.
    ///
    /// Forty-five seconds, not twenty. A cold call was measured at 16.5s on a
    /// Mac where osqueryd's version probe burned its entire fifteen second
    /// timeout, and a limit set just above what has been observed converts the
    /// next slow host into a reported hang. The bound is here to stop waiting
    /// forever, not to police the agent's response time.
    static let readTimeout: TimeInterval = 45

    static func read() -> Snapshot {
        guard let php = resolvePHP() else {
            var s = Snapshot()
            s.failure = "PHP not found. Looked in \(phpCandidates.joined(separator: ", "))."
            return s
        }

        guard FileManager.default.fileExists(atPath: installPath) else {
            var s = Snapshot()
            s.failure = "Agent not found at \(installPath)."
            return s
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: php)
        process.arguments = ["artisan", "ids:status", "--json"]
        process.currentDirectoryURL = URL(fileURLWithPath: installPath)

        let out = Pipe()
        let err = Pipe()
        process.standardOutput = out
        process.standardError = err

        do {
            try process.run()
        } catch {
            var s = Snapshot()
            s.failure = "Could not run the agent: \(error.localizedDescription)"
            return s
        }

        // Terminate it if it overruns. Killing the process closes the pipes,
        // which is what unblocks the reads below — so the timeout is enforced
        // without a second thread having to share state with this one.
        let killer = DispatchWorkItem { [weak process] in process?.terminate() }
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + readTimeout, execute: killer)

        // Read before waiting: a pipe that fills while nobody drains it
        // deadlocks, and the JSON is comfortably larger than the buffer.
        let data = out.fileHandleForReading.readDataToEndOfFile()
        let errorText = String(data: err.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        process.waitUntilExit()
        killer.cancel()

        if process.terminationReason == .uncaughtSignal {
            var s = Snapshot()
            s.failure = "The agent did not answer within \(Int(readTimeout))s — `php artisan ids:status` is hanging."
            return s
        }

        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            var s = Snapshot()
            let trimmed = errorText.trimmingCharacters(in: .whitespacesAndNewlines)
            s.failure = trimmed.isEmpty
                ? "The agent returned nothing readable."
                : String(trimmed.prefix(300))
            return s
        }

        return parse(json)
    }

    /// Read a number without caring how PHP chose to encode it.
    ///
    /// `json_encode` drops the fraction from a whole float, so the same field
    /// arrives as `2` one minute and `1.85` the next. A plain `as? Int` fails
    /// on the second and a plain `as? Double` is fine on both today — but the
    /// failure mode of guessing wrong is a zero rendered as though it were
    /// measured, which is the one thing this console must never do.
    static func num(_ any: Any?) -> Double? {
        switch any {
        case let n as NSNumber: return n.doubleValue
        case let d as Double:   return d
        case let i as Int:      return Double(i)
        default:                return nil
        }
    }

    static func int(_ any: Any?) -> Int? {
        num(any).map { Int($0) }
    }

    static func parse(_ json: [String: Any]) -> Snapshot {
        var s = Snapshot()

        if let host = json["host"] as? [String: Any] {
            s.hostName = host["name"] as? String ?? "—"
            let os = host["os"] as? String ?? ""
            let arch = host["arch"] as? String ?? ""
            s.hostOS = [os, arch].filter { !$0.isEmpty }.joined(separator: " ")
        }

        if let overall = json["overall"] as? [String: Any] {
            s.overall = Health(overall["state"] as? String)
            s.reasons = overall["reasons"] as? [String] ?? []
        }

        if let iso = json["generated_at"] as? String {
            let formatter = ISO8601DateFormatter()
            s.generatedAt = formatter.date(from: iso)
        }

        if let edr = json["edr"] as? [String: Any] {
            let backend = edr["backend"] as? String
            s.rows.append(.init(
                title: "Endpoint sensor",
                detail: backend ?? "no backend",
                health: Health(edr["state"] as? String)
            ))

            if let spool = edr["spool"] as? [String: Any],
               let retention = spool["retention"] as? [String: Any] {
                // Ordered, because "process" is the one that answers most
                // questions and a dictionary would render it anywhere.
                for key in ["process", "network", "identity"] {
                    guard let window = retention[key] as? [String: Any],
                          let events = int(window["events"]),
                          events > 0 else { continue }

                    // hours is genuinely null when the window cannot be
                    // measured, and that stays distinct from zero.
                    s.retention.append((key, events, num(window["hours"])))
                }
            }
        }

        if let c = json["correlator"] as? [String: Any] {
            let health = Health(c["state"] as? String)
            var detail = health.rawValue

            if health == .warming, let w = c["warmup"] as? [String: Any] {
                let observed = num(w["days_observed"]) ?? 0
                let required = int(w["days_required"]) ?? 14
                let percent = int(w["progress"]) ?? 0
                detail = "warming \(percent)% · \(String(format: "%.1f", observed))/\(required) days"
            }

            s.rows.append(.init(title: "Correlator", detail: detail, health: health))
        }

        if let su = json["suricata"] as? [String: Any] {
            var detail = su["version"] as? String ?? "—"
            if let rules = int(su["rules"]), rules > 0 {
                detail += " · \(format(rules)) rules"
            }
            s.rows.append(.init(title: "Suricata", detail: detail, health: Health(su["state"] as? String)))
        }

        if let cl = json["clamav"] as? [String: Any] {
            s.rows.append(.init(
                title: "ClamAV",
                detail: cl["version"] as? String ?? "—",
                health: Health(cl["state"] as? String)
            ))
        }

        if let hub = json["hub"] as? [String: Any] {
            let health = Health(hub["state"] as? String)
            var detail = hub["url"] as? String ?? (hub["detail"] as? String ?? "not configured")

            if let queued = int(hub["queued_alerts"]), queued > 0 {
                detail += " · \(format(queued)) queued"
            }

            s.rows.append(.init(title: "Hub", detail: detail, health: health))
        }

        return s
    }

    static func format(_ n: Int) -> String {
        let f = NumberFormatter()
        f.numberStyle = .decimal
        return f.string(from: NSNumber(value: n)) ?? "\(n)"
    }
}

// MARK: - Menu bar

final class Controller: NSObject, NSApplicationDelegate, NSMenuDelegate {
    /// Created on launch, not at construction.
    ///
    /// A status item made before the app has finished launching is made before
    /// there is a menu bar to put it in: it is allocated, it is retained, every
    /// call on it succeeds, and it never appears. The process stays alive with
    /// nothing on screen and nothing in the log — which is exactly the failure
    /// that is hardest to reason about from the outside, because "running" and
    /// "working" have come apart with no signal in between.
    private var item: NSStatusItem?
    private let menu = NSMenu()
    private var snapshot = Snapshot()
    private var timer: Timer?
    private var refreshing = false

    /// Print what happened and exit, instead of running.
    var diagnose = false

    func applicationDidFinishLaunching(_ notification: Notification) {
        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        self.item = item

        menu.delegate = self
        item.menu = menu

        render()

        if diagnose {
            report(item)
            exit(0)
        }

        refresh()

        // Five minutes, not thirty seconds.
        //
        // Each poll is a whole Laravel boot: measured at 1.1s of CPU and 149MB
        // resident for a single snapshot. Every thirty seconds that is a few
        // percent of a core burned continuously by a program whose entire
        // output is one dot — and the detail behind the dot is only ever read
        // while the menu is open, which triggers its own refresh anyway.
        //
        // So the timer exists only to keep the dot's colour roughly honest
        // between openings, and that does not need to be fast.
        timer = Timer.scheduledTimer(withTimeInterval: 300, repeats: true) { [weak self] _ in
            self?.refresh()
        }
    }

    /// Refreshing when the menu opens keeps the number under the cursor honest.
    func menuWillOpen(_ menu: NSMenu) {
        refresh()
    }

    /// Say out loud what is normally only observable by looking at the screen.
    ///
    /// A missing menu bar icon has two causes that are indistinguishable from
    /// outside the process — it was never created, or it was created and the
    /// menu bar had no room to show it — and no amount of staring at the
    /// screen separates them. So the program reports its own side of it.
    private func report(_ item: NSStatusItem) {
        // Written in two halves, in this order, on purpose.
        //
        // The status item's own state is known the instant this runs; reading
        // the agent shells out and can take twenty seconds or hang outright.
        // Building one string and printing it at the end means the answer we
        // came for is held hostage by the part that fails — which is exactly
        // what happened the first time this ran: it printed nothing at all,
        // and "nothing" was indistinguishable from "never got here".
        var out = "\n"
        out += "Status item\n"
        out += "  created      yes\n"
        out += "  button       \(item.button == nil ? "MISSING — nothing can be drawn" : "present")\n"
        out += "  visible      \(item.isVisible ? "yes" : "NO — the menu bar is not showing it")\n"
        out += "  width        \(item.button.map { String(format: "%.1f pt", $0.frame.width) } ?? "n/a")\n"
        out += "  menu bar     \(String(format: "%.0f pt tall", NSStatusBar.system.thickness))\n"

        if let screen = NSScreen.main {
            out += "  display      \(Int(screen.frame.width))x\(Int(screen.frame.height))"

            // The notch shows up as a safe area inset at the top. When it is
            // present, items can be pushed under it and become unreachable
            // while every API still reports success. Only readable on macOS 12
            // and later, and this builds against 11.
            if #available(macOS 12.0, *), screen.safeAreaInsets.top > 0 {
                out += "  (notched — top inset \(Int(screen.safeAreaInsets.top)) pt)"
            }

            out += "\n"
        }

        out += "\nAgent  (reading, up to \(Int(AgentReader.readTimeout))s…)\n"
        emit(out)

        var tail = ""
        let snap = AgentReader.read()

        if let failure = snap.failure {
            tail += "  UNREACHABLE  \(failure)\n"
        } else {
            tail += "  host         \(snap.hostName)  \(snap.hostOS)\n"
            tail += "  overall      \(snap.overall.rawValue)\n"

            for row in snap.rows {
                let name = row.title.padding(toLength: 17, withPad: " ", startingAt: 0)
                tail += "  \(name) \(row.health.rawValue) · \(row.detail)\n"
            }

            for (name, events, hours) in snap.retention {
                tail += "  \(name) \(events) events · \(hours.map { String(format: "%.1fh", $0) } ?? "unknown")\n"
            }

            for reason in snap.reasons {
                tail += "  needs        \(reason)\n"
            }
        }

        emit(tail)
    }

    private func emit(_ text: String) {
        FileHandle.standardError.write(Data(text.utf8))
    }

    private func refresh() {
        guard !refreshing else { return }
        refreshing = true

        DispatchQueue.global(qos: .utility).async { [weak self] in
            let next = AgentReader.read()

            DispatchQueue.main.async {
                self?.refreshing = false
                self?.snapshot = next
                self?.render()
            }
        }
    }

    private func render() {
        renderButton()
        renderMenu()
    }

    private func renderButton() {
        guard let button = item?.button else { return }

        let health = snapshot.failure == nil ? snapshot.overall : Health.unknown

        // A shield next to the dot, because a lone coloured dot in a crowded
        // menu bar is genuinely hard to find, and someone who cannot find it
        // has no way to tell that from the app not running. Template rendering
        // makes it follow the menu bar the way a native icon does; if the
        // symbol is unavailable the dot alone still works.
        if let shield = NSImage(systemSymbolName: "shield.lefthalf.fill", accessibilityDescription: "Security One") {
            // Sized explicitly. An SF Symbol left at its natural size can come
            // out far wider than a menu bar item should be, and an item that is
            // too wide is one the menu bar may simply decline to show — which
            // looks exactly like the app not running.
            shield.size = NSSize(width: 15, height: 15)
            shield.isTemplate = true
            button.image = shield
            button.imagePosition = .imageLeading
        }

        button.attributedTitle = NSAttributedString(
            string: " " + health.symbol,
            attributes: [
                .foregroundColor: health.color,
                .font: NSFont.systemFont(ofSize: 11),
            ]
        )

        button.toolTip = snapshot.failure ?? "Security One Agent — \(snapshot.hostName)"
    }

    private func renderMenu() {
        menu.removeAllItems()

        menu.addItem(header("Security One Agent"))
        menu.addItem(dim("\(snapshot.hostName)  ·  \(snapshot.hostOS)"))
        menu.addItem(.separator())

        if let failure = snapshot.failure {
            // The console cannot reach the agent. Saying which agent and where
            // beats a bare "unavailable", which sends people looking in the
            // wrong place.
            menu.addItem(dim(wrap(failure)))
            menu.addItem(.separator())
        } else {
            for row in snapshot.rows {
                menu.addItem(statusRow(row))
            }

            if !snapshot.retention.isEmpty {
                menu.addItem(.separator())
                menu.addItem(header("History held"))

                for (name, events, hours) in snapshot.retention {
                    let window = hours.map { String(format: "%.1fh", $0) } ?? "unknown"
                    menu.addItem(dim(String(
                        format: "  %@ %@ · %@",
                        name.padding(toLength: 9, withPad: " ", startingAt: 0),
                        AgentReader.format(events),
                        window
                    )))
                }
            }

            if !snapshot.reasons.isEmpty {
                menu.addItem(.separator())
                menu.addItem(header("Needs attention"))

                for reason in snapshot.reasons {
                    let entry = NSMenuItem(title: wrap(reason), action: nil, keyEquivalent: "")
                    entry.attributedTitle = NSAttributedString(
                        string: wrap(reason),
                        attributes: [
                            .foregroundColor: NSColor.systemYellow,
                            .font: NSFont.menuFont(ofSize: 12),
                        ]
                    )
                    menu.addItem(entry)
                }
            }
        }

        menu.addItem(.separator())

        if let at = snapshot.generatedAt {
            let age = Int(Date().timeIntervalSince(at))
            // Age rather than a timestamp: the question is whether this is
            // current, and a clock face makes the reader do the subtraction.
            menu.addItem(dim(age < 60 ? "Updated just now" : "Updated \(age / 60) min ago"))
        }

        menu.addItem(action("Open full report", #selector(openReport)))
        menu.addItem(action("Refresh now", #selector(refreshNow)))
        menu.addItem(.separator())
        menu.addItem(action("Quit", #selector(quit)))
    }

    // MARK: menu construction helpers

    private func statusRow(_ row: Snapshot.Row) -> NSMenuItem {
        let item = NSMenuItem(title: "", action: nil, keyEquivalent: "")
        let line = NSMutableAttributedString()

        line.append(NSAttributedString(
            string: "\(row.health.symbol)  ",
            attributes: [.foregroundColor: row.health.color, .font: NSFont.menuFont(ofSize: 12)]
        ))
        line.append(NSAttributedString(
            string: row.title.padding(toLength: 17, withPad: " ", startingAt: 0),
            attributes: [.font: NSFont.monospacedDigitSystemFont(ofSize: 12, weight: .medium)]
        ))
        line.append(NSAttributedString(
            string: row.detail,
            attributes: [
                .foregroundColor: NSColor.secondaryLabelColor,
                .font: NSFont.monospacedDigitSystemFont(ofSize: 12, weight: .regular),
            ]
        ))

        item.attributedTitle = line
        return item
    }

    private func header(_ text: String) -> NSMenuItem {
        let item = NSMenuItem(title: text, action: nil, keyEquivalent: "")
        item.attributedTitle = NSAttributedString(
            string: text,
            attributes: [.font: NSFont.systemFont(ofSize: 12, weight: .semibold)]
        )
        return item
    }

    private func dim(_ text: String) -> NSMenuItem {
        let item = NSMenuItem(title: text, action: nil, keyEquivalent: "")
        item.attributedTitle = NSAttributedString(
            string: text,
            attributes: [
                .foregroundColor: NSColor.secondaryLabelColor,
                .font: NSFont.monospacedDigitSystemFont(ofSize: 11, weight: .regular),
            ]
        )
        return item
    }

    private func action(_ title: String, _ selector: Selector) -> NSMenuItem {
        let item = NSMenuItem(title: title, action: selector, keyEquivalent: "")
        item.target = self
        return item
    }

    /// Menu items do not wrap, so a long line is cut rather than silently
    /// running off the edge of the screen.
    private func wrap(_ text: String, limit: Int = 64) -> String {
        text.count <= limit ? text : String(text.prefix(limit - 1)) + "…"
    }

    // MARK: actions

    @objc private func refreshNow() {
        refresh()
    }

    @objc private func openReport() {
        // Opens the same command in Terminal, so the full detail is one click
        // away and is the identical snapshot rather than a second rendering.
        let script = """
        tell application "Terminal"
            activate
            do script "cd \(AgentReader.installPath) && php artisan ids:status; echo; read -n 1 -s -p 'Press any key…'"
        end tell
        """

        if let apple = NSAppleScript(source: script) {
            var error: NSDictionary?
            apple.executeAndReturnError(&error)
        }
    }

    @objc private func quit() {
        NSApplication.shared.terminate(nil)
    }
}

// MARK: - Entry point

let app = NSApplication.shared

// Accessory, not regular: this belongs in the menu bar and has no business
// taking a Dock tile or a window.
app.setActivationPolicy(.accessory)

// Held by a top-level binding on purpose. NSApplication does not retain its
// delegate, and a delegate that is deallocated between here and the first run
// loop pass takes the status item with it — silently, since nothing about a
// missing menu bar icon says why it is missing.
let controller = Controller()
controller.diagnose = CommandLine.arguments.contains("--diagnose")
app.delegate = controller

if controller.diagnose {
    // Printed before the run loop starts, so that silence afterwards means
    // something specific: the process got this far and the delegate never
    // fired. Without it, "no output" covers everything from a bad binary to a
    // launch that succeeded and then blocked, and those need opposite fixes.
    FileHandle.standardError.write(Data("\nStarting run loop…\n".utf8))
}

app.run()
