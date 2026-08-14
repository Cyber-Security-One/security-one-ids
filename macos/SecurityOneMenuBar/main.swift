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

        // Read before waiting: a pipe that fills while nobody drains it
        // deadlocks, and the JSON is comfortably larger than the buffer.
        let data = out.fileHandleForReading.readDataToEndOfFile()
        let errorText = String(data: err.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        process.waitUntilExit()

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

final class Controller: NSObject, NSMenuDelegate {
    private let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    private let menu = NSMenu()
    private var snapshot = Snapshot()
    private var timer: Timer?
    private var refreshing = false

    func start() {
        menu.delegate = self
        item.menu = menu
        render()
        refresh()

        // Half a minute matches the agent's own cycle, so the console is never
        // showing something the agent has already superseded for long.
        timer = Timer.scheduledTimer(withTimeInterval: 30, repeats: true) { [weak self] _ in
            self?.refresh()
        }
    }

    /// Refreshing when the menu opens keeps the number under the cursor honest.
    func menuWillOpen(_ menu: NSMenu) {
        refresh()
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
        guard let button = item.button else { return }

        let health = snapshot.failure == nil ? snapshot.overall : Health.unknown
        let title = NSAttributedString(
            string: health.symbol,
            attributes: [
                .foregroundColor: health.color,
                .font: NSFont.systemFont(ofSize: 13),
            ]
        )

        button.attributedTitle = title
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

let controller = Controller()
controller.start()

app.run()
