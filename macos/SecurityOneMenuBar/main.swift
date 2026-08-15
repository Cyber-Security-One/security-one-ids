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

    /// The snapshot exactly as the agent sent it.
    ///
    /// The menu needs five lines, and the parsed fields above are those five
    /// lines. The detail window needs everything else — spool counters,
    /// warm-up arithmetic, definition dates, the fields that are null on
    /// purpose — and modelling each one a second time would be a second place
    /// to forget to update. It renders from this.
    var raw: [String: Any] = [:]

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

        // Collected through temporary files rather than pipes.
        //
        // A pipe reaches end-of-file only when every copy of its write end has
        // been closed, and `php artisan` is not guaranteed to be the last one
        // holding it: anything it spawns inherits the same descriptor and can
        // outlive it. That is not a hypothetical. The agent's Suricata stats
        // used to leave an orphaned `grep` scanning a 79 GB log for hours, and
        // for as long as one lived, `readDataToEndOfFile()` on this side sat
        // waiting for it. The console stayed running with a dot that never
        // resolved and a menu that never filled, blocked on a process it had
        // never heard of and could not name.
        //
        // A file has no such rule. Once php exits, what it wrote is there to
        // read, and a straggler still holding the descriptor is not this
        // program's problem.
        let scratch = FileManager.default.temporaryDirectory
        let stamp = "\(ProcessInfo.processInfo.processIdentifier)-\(UInt64.random(in: 0 ..< .max))"
        let outURL = scratch.appendingPathComponent("securityone-status-\(stamp).out")
        let errURL = scratch.appendingPathComponent("securityone-status-\(stamp).err")

        defer {
            try? FileManager.default.removeItem(at: outURL)
            try? FileManager.default.removeItem(at: errURL)
        }

        let files = FileManager.default
        guard files.createFile(atPath: outURL.path, contents: nil),
              files.createFile(atPath: errURL.path, contents: nil),
              let outHandle = try? FileHandle(forWritingTo: outURL),
              let errHandle = try? FileHandle(forWritingTo: errURL)
        else {
            var s = Snapshot()
            s.failure = "Could not open a scratch file in \(scratch.path)."
            return s
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: php)
        process.arguments = ["artisan", "ids:status", "--json"]
        process.currentDirectoryURL = URL(fileURLWithPath: installPath)
        process.standardOutput = outHandle
        process.standardError = errHandle

        // Set before run(), so a command that exits immediately cannot signal
        // before there is anything listening.
        let finished = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in finished.signal() }

        do {
            try process.run()
        } catch {
            try? outHandle.close()
            try? errHandle.close()
            var s = Snapshot()
            s.failure = "Could not run the agent: \(error.localizedDescription)"
            return s
        }

        // Bounded, because the answer can legitimately be slow and can also
        // never come: the command shells out to osqueryd and systemctl, each
        // with its own idea of how long to wait.
        //
        // Terminating php is not by itself enough to free a reader blocked on
        // a pipe — a grandchild keeps the descriptor it inherited, which is
        // the bug this replaced. With the output in files there is nothing to
        // free: once the process is gone, what it wrote is readable.
        var timedOut = false
        if finished.wait(timeout: .now() + readTimeout) == .timedOut {
            timedOut = true
            process.terminate()

            if finished.wait(timeout: .now() + 3) == .timedOut {
                kill(process.processIdentifier, SIGKILL)
                _ = finished.wait(timeout: .now() + 3)
            }
        }

        try? outHandle.close()
        try? errHandle.close()

        let data = (try? Data(contentsOf: outURL)) ?? Data()
        let errorText = String(
            data: (try? Data(contentsOf: errURL)) ?? Data(),
            encoding: .utf8
        ) ?? ""

        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            var s = Snapshot()
            let trimmed = errorText.trimmingCharacters(in: .whitespacesAndNewlines)

            if timedOut {
                s.failure = "The agent did not answer within \(Int(readTimeout))s — `php artisan ids:status` is hanging."
            } else {
                s.failure = trimmed.isEmpty
                    ? "The agent returned nothing readable."
                    : String(trimmed.prefix(300))
            }

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
        s.raw = json

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
    private var details: DetailWindow?

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
                self?.details?.update(next)
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

        menu.addItem(action("Agent details…", #selector(showDetails)))
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

    @objc private func showDetails() {
        if details == nil {
            details = DetailWindow(
                onRefresh: { [weak self] in self?.refresh() },
                onOpenReport: { [weak self] in self?.openReport() }
            )
        }

        details?.present(snapshot)

        // What is on screen may be five minutes old, which is fine for a dot
        // and not fine for a window somebody opened in order to read numbers.
        refresh()
    }

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


// MARK: - Detail window

/// A clip view that starts at the top.
///
/// AppKit's origin is bottom-left, so an unflipped scroll view lays a short
/// document against the bottom edge and grows it upward. For a column of cards
/// that reads as a rendering bug.
private final class TopAnchoredClipView: NSClipView {
    override var isFlipped: Bool { true }
}

/// A rounded panel that takes its height from what is inside it.
///
/// NSBox looks like the obvious choice and is not: its content view does not
/// drive the box's own height, so a column of them collapses to nothing and
/// every card draws on top of the last. Pinning the content to all four edges
/// makes the size follow the content, which is the only arrangement that
/// survives a card whose contents change with the snapshot.
private final class CardView: NSView {
    var fill: NSColor = .controlBackgroundColor
    var stroke: NSColor = .separatorColor
    var radius: CGFloat = 10

    init(content: NSView, inset: CGFloat = 14) {
        super.init(frame: .zero)
        content.translatesAutoresizingMaskIntoConstraints = false
        addSubview(content)
        NSLayoutConstraint.activate([
            content.topAnchor.constraint(equalTo: topAnchor, constant: inset),
            content.leadingAnchor.constraint(equalTo: leadingAnchor, constant: inset),
            content.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -inset),
            content.bottomAnchor.constraint(equalTo: bottomAnchor, constant: -inset),
        ])
    }

    required init?(coder: NSCoder) { fatalError("not used") }

    // Drawn rather than layer-backed so the colours follow light and dark
    // without a separate appearance observer.
    override func draw(_ dirtyRect: NSRect) {
        let path = NSBezierPath(
            roundedRect: bounds.insetBy(dx: 0.5, dy: 0.5),
            xRadius: radius,
            yRadius: radius
        )
        fill.setFill()
        path.fill()
        stroke.setStroke()
        path.lineWidth = 1
        path.stroke()
    }
}

/// A ring, for a number that is a fraction of something.
///
/// The correlator's warm-up is the one figure here that is a proportion rather
/// than a count, and it is also the one most often misread as a fault. Drawing
/// it as a ring that fills says "partway through" in a way that "0%" beside a
/// red dot does not.
private final class RingView: NSView {
    var fraction: Double = 0 { didSet { needsDisplay = true } }
    var color: NSColor = .systemTeal { didSet { needsDisplay = true } }

    override var intrinsicContentSize: NSSize { NSSize(width: 76, height: 76) }
    override var wantsUpdateLayer: Bool { false }

    override func draw(_ dirtyRect: NSRect) {
        let rect = bounds.insetBy(dx: 6, dy: 6)
        let center = NSPoint(x: rect.midX, y: rect.midY)
        let radius = min(rect.width, rect.height) / 2

        let track = NSBezierPath()
        track.appendArc(withCenter: center, radius: radius, startAngle: 0, endAngle: 360)
        track.lineWidth = 7
        NSColor.separatorColor.setStroke()
        track.stroke()

        guard fraction > 0 else { return }

        let swept = 360 * CGFloat(max(0, min(1, fraction)))
        let arc = NSBezierPath()
        arc.appendArc(
            withCenter: center,
            radius: radius,
            startAngle: 90,
            endAngle: 90 - swept,
            clockwise: true
        )
        arc.lineWidth = 7
        arc.lineCapStyle = .round
        color.setStroke()
        arc.stroke()
    }
}

/// The snapshot in full, laid out.
///
/// The menu answers "is anything wrong". This answers "what exactly does this
/// agent know about itself", which is a different question and a poor fit for
/// a menu: a menu cannot hold a table, it closes when the pointer leaves it,
/// and most of what `ids:status` returns has nowhere to go in it.
///
/// It decides nothing on its own. Every state, threshold and remedy is the
/// agent's, for the reason given at the top of this file — and a field the
/// agent could not measure renders as a dash rather than as zero, because
/// "unknown" and "none" are different claims and only one of them is reason
/// to relax.
final class DetailWindow: NSObject, NSWindowDelegate {
    private var window: NSWindow?
    private let column = NSStackView()
    private let footnote = NSTextField(labelWithString: "")
    private let onRefresh: () -> Void
    private let onOpenReport: () -> Void
    private var snapshot = Snapshot()

    init(onRefresh: @escaping () -> Void, onOpenReport: @escaping () -> Void) {
        self.onRefresh = onRefresh
        self.onOpenReport = onOpenReport
        super.init()
    }

    var isOpen: Bool { window?.isVisible ?? false }

    func present(_ snapshot: Snapshot) {
        self.snapshot = snapshot

        if window == nil {
            build()
            window?.center()
        }

        rebuild()

        // An accessory app is not in the activation order, so a window it
        // merely orders front arrives behind whatever the operator was using.
        NSApp.activate(ignoringOtherApps: true)
        window?.makeKeyAndOrderFront(nil)
    }

    func update(_ snapshot: Snapshot) {
        self.snapshot = snapshot
        guard isOpen else { return }
        rebuild()
    }

    // MARK: window

    private func build() {
        let w = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 620, height: 760),
            styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        w.title = "Security One Agent"
        w.titlebarAppearsTransparent = true
        w.titleVisibility = .hidden
        w.delegate = self
        w.isReleasedWhenClosed = false
        w.minSize = NSSize(width: 560, height: 420)
        w.isMovableByWindowBackground = true

        // Vibrancy rather than a flat fill: this window sits over whatever the
        // operator was already looking at, and a console that reads as part of
        // the system is less likely to be dismissed as a nag.
        let backdrop = NSVisualEffectView()
        backdrop.material = .underPageBackground
        backdrop.blendingMode = .behindWindow
        backdrop.state = .active
        backdrop.translatesAutoresizingMaskIntoConstraints = false

        column.orientation = .vertical
        column.alignment = .width
        column.spacing = 12
        // Top inset clears the traffic lights, which now float over content.
        column.edgeInsets = NSEdgeInsets(top: 38, left: 18, bottom: 18, right: 18)
        column.translatesAutoresizingMaskIntoConstraints = false

        let scroll = NSScrollView()
        scroll.contentView = TopAnchoredClipView()
        scroll.hasVerticalScroller = true
        scroll.drawsBackground = false
        scroll.documentView = column
        scroll.translatesAutoresizingMaskIntoConstraints = false

        footnote.font = .systemFont(ofSize: 11)
        footnote.textColor = .secondaryLabelColor

        let refresh = NSButton(title: "Refresh", target: self, action: #selector(refreshTapped))
        let report = NSButton(title: "Open full report", target: self, action: #selector(reportTapped))
        for button in [refresh, report] { button.bezelStyle = .rounded }
        refresh.keyEquivalent = "r"

        let bar = NSStackView(views: [footnote, NSView(), report, refresh])
        bar.orientation = .horizontal
        bar.spacing = 8
        bar.edgeInsets = NSEdgeInsets(top: 10, left: 18, bottom: 14, right: 18)
        bar.translatesAutoresizingMaskIntoConstraints = false

        let rule = NSBox()
        rule.boxType = .separator
        rule.translatesAutoresizingMaskIntoConstraints = false

        backdrop.addSubview(scroll)
        backdrop.addSubview(rule)
        backdrop.addSubview(bar)

        NSLayoutConstraint.activate([
            scroll.topAnchor.constraint(equalTo: backdrop.topAnchor),
            scroll.leadingAnchor.constraint(equalTo: backdrop.leadingAnchor),
            scroll.trailingAnchor.constraint(equalTo: backdrop.trailingAnchor),
            scroll.bottomAnchor.constraint(equalTo: rule.topAnchor),

            rule.leadingAnchor.constraint(equalTo: backdrop.leadingAnchor),
            rule.trailingAnchor.constraint(equalTo: backdrop.trailingAnchor),
            rule.bottomAnchor.constraint(equalTo: bar.topAnchor),

            bar.leadingAnchor.constraint(equalTo: backdrop.leadingAnchor),
            bar.trailingAnchor.constraint(equalTo: backdrop.trailingAnchor),
            bar.bottomAnchor.constraint(equalTo: backdrop.bottomAnchor),

            column.topAnchor.constraint(equalTo: scroll.contentView.topAnchor),
            column.leadingAnchor.constraint(equalTo: scroll.contentView.leadingAnchor),
            column.trailingAnchor.constraint(equalTo: scroll.contentView.trailingAnchor),
            column.widthAnchor.constraint(equalTo: scroll.contentView.widthAnchor),
        ])

        w.contentView = backdrop
        window = w
    }

    @objc private func refreshTapped() { onRefresh() }
    @objc private func reportTapped() { onOpenReport() }

    // MARK: content

    private func rebuild() {
        for view in column.arrangedSubviews { view.removeFromSuperview() }

        guard snapshot.failure == nil else {
            add(hero())
            add(card(
                title: "Agent unreachable",
                health: .unknown,
                state: nil,
                body: paragraph(snapshot.failure ?? "")
            ))
            footnote.stringValue = "No snapshot"
            return
        }

        add(hero())

        if !snapshot.reasons.isEmpty {
            add(card(
                title: "Needs attention",
                health: snapshot.overall,
                state: nil,
                body: stack(snapshot.reasons.map { reasonRow($0) })
            ))
        }

        add(edrCard())
        add(correlatorCard())
        add(section("Suricata", "suricata", [
            ("Installed", "installed", .flag),
            ("Running", "running", .flag),
            ("Version", "version", .text),
            ("Mode", "mode", .text),
            ("Rules loaded", "rules", .count),
            ("Remedy", "action", .text),
        ]))
        add(section("ClamAV", "clamav", [
            ("Installed", "installed", .flag),
            ("Version", "version", .text),
            ("Definitions", "definitions_date", .text),
            ("Last scan", "last_scan", .text),
            ("Remedy", "action", .text),
        ]))
        add(section("Hub", "hub", [
            ("Configured", "configured", .flag),
            ("URL", "url", .text),
            ("Queued alerts", "queued_alerts", .count),
            ("Consecutive failures", "consecutive_failures", .count),
            ("Backoff until", "backoff_until", .text),
            ("Detail", "detail", .text),
        ]))

        if let at = snapshot.generatedAt {
            let age = Int(Date().timeIntervalSince(at))
            footnote.stringValue = age < 60
                ? "Snapshot taken just now"
                : "Snapshot taken \(age / 60) min ago"
        } else {
            footnote.stringValue = ""
        }
    }

    /// Added at the column's full width.
    ///
    /// Stack view alignment alone did not hold it: a card narrower than the
    /// column kept its intrinsic width and was set against the trailing edge,
    /// so the hero and the attention card floated right with a dead strip down
    /// the left of the window. An explicit width leaves nothing to infer.
    private func add(_ view: NSView) {
        column.addArrangedSubview(view)
        view.widthAnchor.constraint(
            equalTo: column.widthAnchor,
            constant: -(column.edgeInsets.left + column.edgeInsets.right)
        ).isActive = true
    }

    /// The answer to "is this host all right", before any of the detail.
    private func hero() -> NSView {
        let state = NSTextField(labelWithString: snapshot.overall.rawValue.uppercased())
        state.font = .systemFont(ofSize: 30, weight: .bold)
        state.textColor = snapshot.overall.color

        let name = NSTextField(labelWithString: snapshot.hostName)
        name.font = .systemFont(ofSize: 15, weight: .semibold)

        let system = NSTextField(labelWithString: [snapshot.hostOS, agentPath()]
            .filter { !$0.isEmpty }
            .joined(separator: "  ·  "))
        system.font = .monospacedDigitSystemFont(ofSize: 11, weight: .regular)
        system.textColor = .secondaryLabelColor
        system.lineBreakMode = .byTruncatingMiddle

        let text = NSStackView(views: [state, name, system])
        text.orientation = .vertical
        text.alignment = .leading
        text.spacing = 2

        let body = NSStackView(views: [text, NSView()])
        body.orientation = .horizontal
        body.alignment = .centerY

        let whole = NSStackView(views: [body, chipRow(), privilegeNote()])
        whole.orientation = .vertical
        whole.alignment = .leading
        whole.spacing = 12

        let card = CardView(content: whole, inset: 16)
        card.fill = snapshot.overall.color.withAlphaComponent(0.10)
        card.stroke = snapshot.overall.color.withAlphaComponent(0.35)
        card.radius = 12
        return card
    }

    private func agentPath() -> String {
        guard let host = snapshot.raw["host"] as? [String: Any] else { return "" }
        return host["agent_path"] as? String ?? ""
    }

    /// Every subsystem at a glance, in the order the menu lists them.
    private func chipRow() -> NSView {
        let row = NSStackView(views: snapshot.rows.map { chip($0.title, $0.health) } + [NSView()])
        row.orientation = .horizontal
        row.spacing = 6
        row.alignment = .centerY
        return row
    }

    private func chip(_ title: String, _ health: Health) -> NSView {
        let dot = NSTextField(labelWithString: health.symbol)
        dot.font = .systemFont(ofSize: 9)
        dot.textColor = health.color

        let name = NSTextField(labelWithString: title)
        name.font = .systemFont(ofSize: 11, weight: .medium)
        name.textColor = .labelColor
        name.lineBreakMode = .byTruncatingTail

        let content = NSStackView(views: [dot, name])
        content.orientation = .horizontal
        content.spacing = 5

        let card = CardView(content: content, inset: 7)
        card.fill = health.color.withAlphaComponent(0.12)
        card.stroke = health.color.withAlphaComponent(0.30)
        card.radius = 7
        return card
    }

    /// Unprivileged is not a fault, but it is why several fields below read
    /// "unknown" — so it is stated rather than left to be inferred.
    private func privilegeNote() -> NSView {
        guard let host = snapshot.raw["host"] as? [String: Any],
              let privileged = host["privileged"] as? Bool,
              !privileged
        else { return NSView() }

        let note = NSTextField(labelWithString:
            "Reading unprivileged — fields the agent could not determine show as “—”, not as zero.")
        note.font = .systemFont(ofSize: 11)
        note.textColor = .secondaryLabelColor
        note.lineBreakMode = .byTruncatingTail
        return note
    }

    private func edrCard() -> NSView {
        let edr = snapshot.raw["edr"] as? [String: Any]
        let body = NSStackView()
        body.orientation = .vertical
        body.alignment = .width
        body.spacing = 10

        body.addArrangedSubview(fields([
            ("Backend", value(edr, "backend", .text)),
            ("Installed", value(edr, "installed", .flag)),
            ("Running", value(edr, "running", .flag)),
            ("Version", value(edr, "version", .text)),
            ("PID", value(edr, "pid", .count)),
            ("Container visibility", value(edr, "container_visibility", .text)),
            ("Event clock anchorable", value(edr, "event_clock_anchorable", .flag)),
            ("Remedy", value(edr, "action", .text)),
        ]))

        if let spool = edr?["spool"] as? [String: Any] {
            body.addArrangedSubview(divider())
            body.addArrangedSubview(subheading("Event spool"))
            body.addArrangedSubview(fields([
                ("Total events", value(spool, "total_events", .count)),
                ("Pending upload", value(spool, "pending_upload", .count)),
                ("Sent", value(spool, "sent", .count)),
                ("With alerts", value(spool, "with_alerts", .count)),
                ("On disk", value(spool, "size_bytes", .bytes)),
            ]))

            body.addArrangedSubview(divider())
            body.addArrangedSubview(subheading("History held"))
            body.addArrangedSubview(retentionTable(spool["retention"] as? [String: Any]))
        }

        return card(
            title: "Endpoint sensor",
            health: Health(edr?["state"] as? String),
            state: edr?["state"] as? String,
            body: body
        )
    }

    /// Per class, never averaged.
    ///
    /// The classes have separate ceilings, so a single figure across the spool
    /// reports the long tail of a small class as though it were the window
    /// everything has — reading as 67 hours of history on a host whose process
    /// telemetry reaches back under two.
    private func retentionTable(_ retention: [String: Any]?) -> NSView {
        let grid = NSGridView(numberOfColumns: 3, rows: 0)
        grid.translatesAutoresizingMaskIntoConstraints = false
        grid.rowSpacing = 5
        grid.columnSpacing = 18

        grid.addRow(with: [
            columnHeading("Class"), columnHeading("Events"), columnHeading("Reaches back"),
        ])

        for key in ["process", "network", "identity"] {
            let window = retention?[key] as? [String: Any]
            let events = AgentReader.int(window?["events"])
            let hours = AgentReader.num(window?["hours"])

            let span: Cell
            if let hours = hours {
                span = Cell(text: String(format: "%.1f h", hours), kind: .plain)
            } else if events == 0 {
                span = Cell(text: "no events yet", kind: .muted)
            } else {
                span = Cell(text: "unknown", kind: .absent)
            }

            grid.addRow(with: [
                label(key, color: .labelColor),
                cellView(events.map { Cell(text: AgentReader.format($0), kind: .plain) }
                    ?? Cell(text: "—", kind: .absent)),
                cellView(span),
            ])
        }

        grid.column(at: 1).xPlacement = .trailing
        return grid
    }

    private func correlatorCard() -> NSView {
        let c = snapshot.raw["correlator"] as? [String: Any]
        let health = Health(c?["state"] as? String)
        let body = NSStackView()
        body.orientation = .vertical
        body.alignment = .width
        body.spacing = 10

        body.addArrangedSubview(fields([
            ("Enabled", value(c, "enabled", .flag)),
            ("Mature", value(c, "mature", .flag)),
            ("Clock anomalies", value(c, "clock_anomalies", .count)),
        ]))

        // Warming is not a fault. The correlator is silent by design for its
        // first fortnight while it learns what this host normally does, and a
        // red dot for two weeks teaches people to ignore red.
        if let warmup = c?["warmup"] as? [String: Any] {
            let observed = AgentReader.num(warmup["days_observed"]) ?? 0
            let required = AgentReader.int(warmup["days_required"]) ?? 14
            let events = AgentReader.int(warmup["events"]) ?? 0
            let needed = AgentReader.int(warmup["events_required"]) ?? 0
            let progress = AgentReader.int(warmup["progress"]) ?? 0

            let ring = RingView()
            ring.fraction = Double(progress) / 100
            ring.color = health == .disabled ? .tertiaryLabelColor : Health.warming.color
            ring.translatesAutoresizingMaskIntoConstraints = false

            let percent = NSTextField(labelWithString: "\(progress)%")
            percent.font = .monospacedDigitSystemFont(ofSize: 15, weight: .semibold)
            percent.alignment = .center
            percent.translatesAutoresizingMaskIntoConstraints = false

            let dial = NSView()
            dial.translatesAutoresizingMaskIntoConstraints = false
            dial.addSubview(ring)
            dial.addSubview(percent)

            NSLayoutConstraint.activate([
                ring.topAnchor.constraint(equalTo: dial.topAnchor),
                ring.bottomAnchor.constraint(equalTo: dial.bottomAnchor),
                ring.leadingAnchor.constraint(equalTo: dial.leadingAnchor),
                ring.trailingAnchor.constraint(equalTo: dial.trailingAnchor),
                ring.widthAnchor.constraint(equalToConstant: 76),
                ring.heightAnchor.constraint(equalToConstant: 76),
                percent.centerXAnchor.constraint(equalTo: ring.centerXAnchor),
                percent.centerYAnchor.constraint(equalTo: ring.centerYAnchor),
            ])

            let numbers = fields([
                ("Days observed", Cell(text: String(format: "%.1f of %d", observed, required), kind: .plain)),
                ("Events seen", Cell(
                    text: "\(AgentReader.format(events)) of \(AgentReader.format(needed))",
                    kind: .plain
                )),
            ])

            let side = NSStackView(views: [subheading("Warm-up"), numbers])
            side.orientation = .vertical
            side.alignment = .leading
            side.spacing = 6

            let pair = NSStackView(views: [dial, side])
            pair.orientation = .horizontal
            pair.alignment = .centerY
            pair.spacing = 16

            body.addArrangedSubview(divider())
            body.addArrangedSubview(pair)
        }

        if let learned = c?["learned"] as? [String: Any] {
            body.addArrangedSubview(divider())
            body.addArrangedSubview(subheading("Learned"))
            body.addArrangedSubview(fields([
                ("Facets", value(learned, "facets", .count)),
                ("Actors", value(learned, "actors", .count)),
                ("Lineage rows", value(learned, "lineage_rows", .count)),
                ("Incidents seen", value(learned, "incidents_seen", .count)),
            ]))
        }

        return card(
            title: "Correlator",
            health: health,
            state: c?["state"] as? String,
            body: body
        )
    }

    private func section(_ title: String, _ key: String, _ spec: [(String, String, Kind)]) -> NSView {
        let source = snapshot.raw[key] as? [String: Any]
        return card(
            title: title,
            health: Health(source?["state"] as? String),
            state: source?["state"] as? String,
            body: fields(spec.map { ($0.0, value(source, $0.1, $0.2)) })
        )
    }

    // MARK: cells

    enum Kind { case text, flag, count, bytes }

    /// How a value should read, kept apart from what it says, so a caller that
    /// passes only a string cannot accidentally present "could not measure" as
    /// though it were a measurement.
    struct Cell {
        enum Style { case plain, muted, absent }
        let text: String
        let kind: Style
    }

    private func value(_ source: Any?, _ key: String, _ kind: Kind) -> Cell {
        guard let dict = source as? [String: Any] else { return Cell(text: "—", kind: .absent) }
        let raw = dict[key]

        if raw == nil || raw is NSNull { return Cell(text: "—", kind: .absent) }

        switch kind {
        case .flag:
            let on = (raw as? Bool) ?? false
            return Cell(text: on ? "yes" : "no", kind: .plain)
        case .count:
            guard let n = AgentReader.int(raw) else { return Cell(text: "—", kind: .absent) }
            return Cell(text: AgentReader.format(n), kind: .plain)
        case .bytes:
            guard let n = AgentReader.num(raw) else { return Cell(text: "—", kind: .absent) }
            return Cell(text: humanBytes(n), kind: .plain)
        case .text:
            let text = String(describing: raw!)
            return Cell(text: text.isEmpty ? "—" : text, kind: text.isEmpty ? .absent : .plain)
        }
    }

    private func humanBytes(_ n: Double) -> String {
        let units = ["B", "KB", "MB", "GB", "TB"]
        var value = n
        var unit = 0
        while value >= 1024, unit < units.count - 1 {
            value /= 1024
            unit += 1
        }
        return unit == 0 ? "\(Int(value)) B" : String(format: "%.1f %@", value, units[unit])
    }

    // MARK: chrome

    private func card(title: String, health: Health?, state: String?, body: NSView) -> NSView {
        let heading = NSStackView(views: [])
        heading.orientation = .horizontal
        heading.spacing = 8
        heading.alignment = .centerY

        if let health = health {
            let dot = NSTextField(labelWithString: health.symbol)
            dot.font = .systemFont(ofSize: 12)
            dot.textColor = health.color
            heading.addArrangedSubview(dot)
        }

        let name = NSTextField(labelWithString: title)
        name.font = .systemFont(ofSize: 13, weight: .semibold)
        heading.addArrangedSubview(name)
        heading.addArrangedSubview(NSView())

        if let state = state, let health = health {
            let badge = NSTextField(labelWithString: state.uppercased())
            badge.font = .systemFont(ofSize: 10, weight: .semibold)
            badge.textColor = health.color
            heading.addArrangedSubview(badge)
        }

        let content = NSStackView(views: [heading, body])
        content.orientation = .vertical
        content.alignment = .width
        content.spacing = 10

        let card = CardView(content: content, inset: 15)
        card.fill = .controlBackgroundColor.withAlphaComponent(0.55)
        card.stroke = .separatorColor
        return card
    }

    private func fields(_ rows: [(String, Cell)]) -> NSView {
        let grid = NSGridView(numberOfColumns: 2, rows: 0)
        grid.translatesAutoresizingMaskIntoConstraints = false
        grid.rowSpacing = 5
        grid.columnSpacing = 14

        for (name, cell) in rows {
            grid.addRow(with: [label(name, color: .secondaryLabelColor), cellView(cell)])
        }

        grid.column(at: 0).width = 176
        return grid
    }

    private func cellView(_ cell: Cell) -> NSView {
        let field = NSTextField(labelWithString: cell.text)
        field.font = .monospacedDigitSystemFont(ofSize: 12, weight: .regular)
        field.lineBreakMode = .byTruncatingTail
        field.isSelectable = true

        // A remedy line is long enough to demand more width than the window
        // has. Left at the default, that demand wins, the column grows wider
        // than the scroll view, and every card is dragged out of alignment by
        // one string. It truncates instead.
        field.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)

        switch cell.kind {
        case .plain:  field.textColor = .labelColor
        case .muted:  field.textColor = .secondaryLabelColor
        case .absent: field.textColor = .tertiaryLabelColor
        }

        return field
    }

    private func label(_ text: String, color: NSColor) -> NSTextField {
        let field = NSTextField(labelWithString: text)
        field.font = .systemFont(ofSize: 12)
        field.textColor = color
        return field
    }

    private func columnHeading(_ text: String) -> NSTextField {
        let field = NSTextField(labelWithString: text.uppercased())
        field.font = .systemFont(ofSize: 10, weight: .semibold)
        field.textColor = .tertiaryLabelColor
        return field
    }

    /// Wrapped with a trailing spacer rather than returned bare.
    ///
    /// The card stacks its rows to equal width, which stretches a lone label
    /// to the full card and leaves where the text sits inside it up to the
    /// cell — and it sat on the right, so every sub-heading floated away from
    /// the rows it was labelling. The spacer takes the slack instead.
    private func subheading(_ text: String) -> NSView {
        let field = NSTextField(labelWithString: text)
        field.font = .systemFont(ofSize: 12, weight: .semibold)
        field.textColor = .labelColor

        let row = NSStackView(views: [field, NSView()])
        row.orientation = .horizontal
        row.spacing = 0
        return row
    }

    private func paragraph(_ text: String) -> NSView {
        let field = NSTextField(wrappingLabelWithString: text)
        field.font = .systemFont(ofSize: 12)
        field.textColor = .labelColor
        field.isSelectable = true
        return field
    }

    private func reasonRow(_ text: String) -> NSView {
        let field = NSTextField(wrappingLabelWithString: text)
        field.font = .monospacedDigitSystemFont(ofSize: 11, weight: .regular)
        field.textColor = .systemYellow
        field.isSelectable = true

        // Same reason as subheading(): stretched to the card's width, the cell
        // put the text on the right, and a remedy that drifts away from the
        // fault it belongs to reads as though it belonged to something else.
        let row = NSStackView(views: [field, NSView()])
        row.orientation = .horizontal
        row.spacing = 0
        return row
    }

    private func stack(_ views: [NSView]) -> NSView {
        let s = NSStackView(views: views)
        s.orientation = .vertical
        s.alignment = .leading
        s.spacing = 6
        return s
    }

    private func divider() -> NSView {
        let line = NSBox()
        line.boxType = .separator
        line.translatesAutoresizingMaskIntoConstraints = false
        return line
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
