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
import SceneKit

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

/// One row from the endpoint sensor's spool.
///
/// Deliberately thin. The console draws events; it does not investigate them,
/// and the fields it does not draw are fields it has no business holding —
/// command lines above all, which are where a secret that slipped past
/// redaction would be.
struct AgentEvent {
    let at: Date
    let action: String
    let severity: String?
    let path: String
    let pid: Int?
    let user: String
    /// Bound for the Hub. Most rows are not: shipping every event would be
    /// hundreds of megabytes a day per host, which is the whole reason
    /// detection runs on the endpoint.
    let deliver: Bool
    let sent: Bool

    var isAlert: Bool { severity != nil }
}

/// What the console asked for, and what the spool actually holds.
///
/// The two are not the same number and the difference matters. A host can hold
/// half a million events; drawing the most recent few thousand of them is the
/// only workable thing to do, and saying "5,281 events" while sitting on
/// 512,904 would misrepresent the size of the haystack in the direction that
/// makes an investigator stop looking.
struct EventFeed {
    var events: [AgentEvent] = []
    /// Rows in the spool. Nil when the agent could not count them.
    var held: Int?

    var truncated: Bool {
        guard let held = held else { return false }
        return held > events.count
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

    /// Run one agent command and hand back what it wrote.
    ///
    /// Shared by the status snapshot and the event feed so that the pipe rule,
    /// the deadline and the escalation to SIGKILL are decided once. They were
    /// worth getting right once and are not worth getting right twice.
    static func invoke(_ arguments: [String]) -> (data: Data, error: String, timedOut: Bool)? {
        guard let php = resolvePHP(),
              FileManager.default.fileExists(atPath: installPath)
        else { return nil }

        let scratch = FileManager.default.temporaryDirectory
        let stamp = "\(ProcessInfo.processInfo.processIdentifier)-\(UInt64.random(in: 0 ..< .max))"
        let outURL = scratch.appendingPathComponent("securityone-\(stamp).out")
        let errURL = scratch.appendingPathComponent("securityone-\(stamp).err")

        defer {
            try? FileManager.default.removeItem(at: outURL)
            try? FileManager.default.removeItem(at: errURL)
        }

        let files = FileManager.default
        guard files.createFile(atPath: outURL.path, contents: nil),
              files.createFile(atPath: errURL.path, contents: nil),
              let outHandle = try? FileHandle(forWritingTo: outURL),
              let errHandle = try? FileHandle(forWritingTo: errURL)
        else { return nil }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: php)
        process.arguments = arguments
        process.currentDirectoryURL = URL(fileURLWithPath: installPath)
        process.standardOutput = outHandle
        process.standardError = errHandle

        let finished = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in finished.signal() }

        do {
            try process.run()
        } catch {
            try? outHandle.close()
            try? errHandle.close()
            return nil
        }

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

        return (
            (try? Data(contentsOf: outURL)) ?? Data(),
            String(data: (try? Data(contentsOf: errURL)) ?? Data(), encoding: .utf8) ?? "",
            timedOut
        )
    }

    /// The most recent events the sensor has spooled.
    ///
    /// Read through `ids:events` rather than out of the spool's SQLite file.
    /// The spool owns its schema, its decryption and its redaction, and a
    /// second reader that opened the file directly would be a second
    /// implementation of all three — one that keeps working, quietly wrongly,
    /// the day any of them changes.
    /// The ceiling on what one console draw will hold.
    ///
    /// Not a guess at what looks good: it is the point past which the read
    /// itself gets slow and the scene stops being legible anyway. When the
    /// spool holds more, the console says so rather than quietly drawing a
    /// fraction.
    static let eventCeiling = 4000

    static func events(limit: Int = eventCeiling) -> EventFeed {
        guard let result = invoke(["artisan", "ids:events", "--json", "--limit=\(limit)"]),
              let json = try? JSONSerialization.jsonObject(with: result.data) as? [String: Any],
              let rows = json["events"] as? [[String: Any]]
        else { return EventFeed() }

        var feed = EventFeed()
        feed.held = int(json["held"])
        feed.events = rows.compactMap { row in
            guard let ts = int(row["ts"]) else { return nil }

            return AgentEvent(
                at: Date(timeIntervalSince1970: TimeInterval(ts)),
                action: row["action"] as? String ?? "unknown",
                severity: row["severity"] as? String,
                path: row["path"] as? String ?? "",
                pid: int(row["pid"]),
                user: row["user"] as? String ?? "",
                deliver: (row["deliver"] as? Bool) ?? false,
                sent: (row["sent"] as? Bool) ?? false
            )
        }

        return feed
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
    private var console: ConsoleWindow?

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

                // Only fetched when something is showing it: the event feed is
                // a second agent invocation, and paying for it to keep a
                // closed window current would be a cost for nothing.
                if self?.console?.isOpen == true {
                    DispatchQueue.global(qos: .utility).async {
                        let feed = AgentReader.events()

                        DispatchQueue.main.async {
                            self?.console?.update(next, feed: feed)
                        }
                    }
                }
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

        menu.addItem(action("Console…", #selector(showConsole)))
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

    @objc private func showConsole() {
        if console == nil {
            console = ConsoleWindow(onRefresh: { [weak self] in self?.refresh() })
        }

        let current = snapshot
        console?.present(current, feed: EventFeed())

        // Opened before the events arrive, on purpose. Reading them takes a
        // second or two, and a window that appears immediately and fills is
        // easier to trust than one that appears only once everything is ready.
        DispatchQueue.global(qos: .utility).async { [weak self] in
            let feed = AgentReader.events()

            DispatchQueue.main.async {
                self?.console?.update(current, feed: feed)
            }
        }

        refresh()
    }

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


// MARK: - 3D console

/// The agent as a scene rather than a list.
///
/// This is the one view here that is not simply a rendering of the snapshot,
/// so it is worth being explicit about what it is for. A list answers "what is
/// the value of this field". A room answers "where is the weight" — which
/// subsystem is dark, whether the events are one steady drift or a burst, how
/// much of what the sensor holds is alerting and how much is retro-hunt
/// material. Those are shape questions, and shape is what an eye is good at.
///
/// The rules from the rest of the file still hold and are what keep it from
/// being decoration: colour comes from the agent's own state and nowhere else,
/// a subsystem the agent could not determine is grey rather than green, and
/// nothing is drawn that was not measured. An event the console invented would
/// be worse than an empty scene.
final class ConsoleWindow: NSObject, NSWindowDelegate {
    private var window: NSWindow?
    private let sceneView = SCNView()
    private let scene = SCNScene()

    /// Everything that turns with the camera drag lives under here, so the
    /// scene can be spun as one object without the lights swinging with it.
    private let world = SCNNode()
    private let eventField = SCNNode()
    private let ringNode = SCNNode()
    private var coreNode = SCNNode()

    private let headline = NSTextField(labelWithString: "")
    private let subhead = NSTextField(labelWithString: "")
    private let legend = NSTextField(labelWithString: "")
    private let footnote = NSTextField(labelWithString: "")
    private let transmission = NSTextField(labelWithString: "")

    private let onRefresh: () -> Void
    private var snapshot = Snapshot()
    private var feed = EventFeed()
    private var events: [AgentEvent] { feed.events }

    init(onRefresh: @escaping () -> Void) {
        self.onRefresh = onRefresh
        super.init()
    }

    var isOpen: Bool { window?.isVisible ?? false }

    func present(_ snapshot: Snapshot, feed: EventFeed) {
        self.snapshot = snapshot
        self.feed = feed

        if window == nil {
            build()
            window?.center()
        }

        rebuild()
        NSApp.activate(ignoringOtherApps: true)
        window?.makeKeyAndOrderFront(nil)
    }

    func update(_ snapshot: Snapshot, feed: EventFeed) {
        self.snapshot = snapshot
        self.feed = feed
        guard isOpen else { return }
        rebuild()
    }

    // MARK: scene construction

    /// The palette.
    ///
    /// Deliberately narrow and cold. The health colours still carry every
    /// verdict — that rule does not bend for looks — but everything that is
    /// not a verdict is drawn in one dim cyan so the coloured things are the
    /// only coloured things. A scene where the furniture is as loud as the
    /// signal is a scene you have to read twice.
    private enum Palette {
        static let deep = NSColor(calibratedRed: 0.023, green: 0.031, blue: 0.055, alpha: 1)
        static let horizon = NSColor(calibratedRed: 0.043, green: 0.075, blue: 0.118, alpha: 1)
        static let structure = NSColor(calibratedRed: 0.25, green: 0.62, blue: 0.78, alpha: 1)
        static let quiet = NSColor(calibratedRed: 0.30, green: 0.72, blue: 0.85, alpha: 1)
        static let alert = NSColor(calibratedRed: 1.00, green: 0.35, blue: 0.42, alpha: 1)
    }

    private func build() {
        let w = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 980, height: 660),
            styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        w.title = "Security One — Console"
        w.titlebarAppearsTransparent = true
        w.titleVisibility = .hidden
        w.delegate = self
        w.isReleasedWhenClosed = false
        w.minSize = NSSize(width: 760, height: 520)

        scene.background.contents = backdropImage()

        // Metal takes its appearance from what is around it. With no
        // environment to reflect, a high-metalness chassis renders as a black
        // silhouette — which is exactly what the first attempt looked like.
        scene.lightingEnvironment.contents = backdropImage()
        scene.lightingEnvironment.intensity = 3.4

        // Fog, so distance reads as distance. Without it the far side of the
        // event shell is exactly as bright as the near side and the whole
        // thing flattens into a disc of dots.
        scene.fogColor = Palette.deep
        scene.fogStartDistance = 30
        scene.fogEndDistance = 95
        scene.fogDensityExponent = 1.6

        scene.rootNode.addChildNode(world)
        world.addChildNode(eventField)
        world.addChildNode(ringNode)

        let camera = SCNNode()
        let lens = SCNCamera()
        lens.fieldOfView = 44
        lens.zFar = 400

        // HDR and bloom are what separate "emissive material" from "this thing
        // is glowing". Everything below is lit dimly and allowed to bloom,
        // rather than being painted bright and looking like plastic.
        lens.wantsHDR = true
        lens.bloomIntensity = 0.95
        lens.bloomThreshold = 0.58
        lens.bloomBlurRadius = 14
        lens.wantsExposureAdaptation = false
        lens.vignettingIntensity = 0.62
        lens.vignettingPower = 1.35
        lens.colorFringeStrength = 0.35
        camera.camera = lens
        camera.position = SCNVector3(CGFloat(0), CGFloat(11), CGFloat(34))
        camera.look(at: SCNVector3(CGFloat(0), CGFloat(0), CGFloat(0)))
        scene.rootNode.addChildNode(camera)

        let ambient = SCNNode()
        ambient.light = SCNLight()
        ambient.light?.type = .ambient
        ambient.light?.intensity = 140
        ambient.light?.color = NSColor(calibratedRed: 0.35, green: 0.45, blue: 0.60, alpha: 1)
        scene.rootNode.addChildNode(ambient)

        let lamps: [SCNVector3] = [
            SCNVector3(CGFloat(12), CGFloat(14), CGFloat(16)),
            SCNVector3(CGFloat(-14), CGFloat(-4), CGFloat(-10)),
        ]

        for position in lamps {
            let lamp = SCNNode()
            lamp.light = SCNLight()
            lamp.light?.type = .omni
            lamp.light?.intensity = 620
            lamp.light?.color = NSColor(calibratedRed: 0.55, green: 0.72, blue: 0.95, alpha: 1)
            lamp.position = position
            scene.rootNode.addChildNode(lamp)
        }

        eventField.runAction(.repeatForever(
            .rotateBy(x: 0, y: CGFloat.pi * 2, z: 0, duration: 120)
        ))

        sceneView.scene = scene
        sceneView.allowsCameraControl = true
        sceneView.autoenablesDefaultLighting = false
        sceneView.antialiasingMode = .multisampling4X
        sceneView.translatesAutoresizingMaskIntoConstraints = false

        headline.font = .monospacedDigitSystemFont(ofSize: 30, weight: .bold)
        subhead.font = .monospacedDigitSystemFont(ofSize: 10, weight: .medium)
        subhead.textColor = NSColor(calibratedWhite: 0.62, alpha: 1)
        legend.font = .monospacedDigitSystemFont(ofSize: 10, weight: .regular)
        legend.textColor = NSColor(calibratedWhite: 0.52, alpha: 1)
        footnote.font = .monospacedDigitSystemFont(ofSize: 10, weight: .regular)
        footnote.textColor = NSColor(calibratedWhite: 0.36, alpha: 1)

        transmission.font = .monospacedDigitSystemFont(ofSize: 10, weight: .regular)
        transmission.textColor = NSColor(calibratedWhite: 0.52, alpha: 1)

        for field in [headline, subhead, legend, footnote, transmission] {
            field.translatesAutoresizingMaskIntoConstraints = false
            field.drawsBackground = false
        }

        let rule = NSBox()
        rule.boxType = .custom
        rule.borderWidth = 0
        rule.fillColor = Palette.structure.withAlphaComponent(0.35)
        rule.translatesAutoresizingMaskIntoConstraints = false
        rule.heightAnchor.constraint(equalToConstant: 1).isActive = true
        rule.widthAnchor.constraint(equalToConstant: 168).isActive = true

        let hud = NSStackView(views: [headline, subhead, rule, legend, transmission])
        hud.orientation = .vertical
        hud.alignment = .leading
        hud.spacing = 6
        hud.setCustomSpacing(9, after: subhead)
        hud.setCustomSpacing(9, after: rule)
        hud.translatesAutoresizingMaskIntoConstraints = false

        let refresh = NSButton(title: "Refresh", target: self, action: #selector(refreshTapped))
        refresh.bezelStyle = .rounded
        refresh.keyEquivalent = "r"
        refresh.translatesAutoresizingMaskIntoConstraints = false

        let root = NSView()
        root.addSubview(sceneView)
        root.addSubview(hud)
        root.addSubview(footnote)
        root.addSubview(refresh)

        NSLayoutConstraint.activate([
            sceneView.topAnchor.constraint(equalTo: root.topAnchor),
            sceneView.leadingAnchor.constraint(equalTo: root.leadingAnchor),
            sceneView.trailingAnchor.constraint(equalTo: root.trailingAnchor),
            sceneView.bottomAnchor.constraint(equalTo: root.bottomAnchor),

            hud.topAnchor.constraint(equalTo: root.topAnchor, constant: 42),
            hud.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 28),

            footnote.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 28),
            footnote.bottomAnchor.constraint(equalTo: root.bottomAnchor, constant: -20),

            refresh.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -22),
            refresh.bottomAnchor.constraint(equalTo: root.bottomAnchor, constant: -20),
        ])

        w.contentView = root
        window = w

        buildFloor()
    }

    /// A vertical gradient rather than a flat fill: a single colour behind a
    /// dark scene has no horizon and the scene appears to float in nothing.
    private func backdropImage() -> NSImage {
        let size = NSSize(width: 2, height: 512)
        let image = NSImage(size: size)
        image.lockFocus()

        let gradient = NSGradient(colors: [
            Palette.deep,
            Palette.horizon,
            Palette.deep,
        ], atLocations: [0.0, 0.55, 1.0], colorSpace: .deviceRGB)

        gradient?.draw(in: NSRect(origin: .zero, size: size), angle: 90)
        image.unlockFocus()

        return image
    }

    /// Text drawn into an image and hung on a plane.
    ///
    /// SCNText extrudes a 3D solid, which at this size reads as chrome
    /// lettering rather than as a label, and it is expensive per glyph. A flat
    /// texture stays crisp, costs one quad, and can be dimmed like everything
    /// else in the scene.
    private func labelNode(_ text: String, color: NSColor, size: CGFloat) -> SCNNode {
        let scale: CGFloat = 64
        let font = NSFont.monospacedDigitSystemFont(ofSize: scale * 0.5, weight: .semibold)
        let attributes: [NSAttributedString.Key: Any] = [
            .font: font,
            .foregroundColor: color,
            .kern: scale * 0.03,
        ]

        let measured = (text as NSString).size(withAttributes: attributes)
        let width: CGFloat = ceil(measured.width) + 12
        let height: CGFloat = ceil(measured.height) + 8

        let image = NSImage(size: NSSize(width: width, height: height))
        image.lockFocus()
        (text as NSString).draw(at: NSPoint(x: 6, y: 4), withAttributes: attributes)
        image.unlockFocus()

        let aspect: CGFloat = width / height
        let plane = SCNPlane(width: size * aspect, height: size)
        let material = SCNMaterial()
        material.diffuse.contents = image
        material.emission.contents = NSColor.clear
        material.isDoubleSided = true
        material.writesToDepthBuffer = false
        material.lightingModel = .constant
        plane.materials = [material]

        let node = SCNNode(geometry: plane)
        node.constraints = [SCNBillboardConstraint()]
        return node
    }

    /// A radial grid under everything.
    ///
    /// It carries no data and is not pretending to. It is there because a
    /// floating object with nothing behind it has no scale and no depth, and
    /// the eye cannot tell an orbit from a flat circle without one.
    private func buildFloor() {
        let floor = SCNNode()
        floor.position = SCNVector3(CGFloat(0), CGFloat(-5.2), CGFloat(0))

        for step in 1 ... 6 {
            let radius: CGFloat = CGFloat(step) * 3.4
            let ring = SCNTorus(ringRadius: radius, pipeRadius: 0.012)
            ring.ringSegmentCount = 96
            ring.pipeSegmentCount = 4

            let material = SCNMaterial()
            let fade: CGFloat = 0.20 - CGFloat(step) * 0.022
            material.diffuse.contents = Palette.structure.withAlphaComponent(max(0.10, fade * 2))
            material.emission.contents = Palette.structure.withAlphaComponent(max(0.06, fade))
            material.lightingModel = .constant
            material.writesToDepthBuffer = false
            ring.materials = [material]

            floor.addChildNode(SCNNode(geometry: ring))
        }

        for spoke in 0 ..< 12 {
            let angle: CGFloat = (CGFloat(spoke) / 12) * 2 * CGFloat.pi
            let length: CGFloat = 20.4
            let bar = SCNCylinder(radius: 0.008, height: length)

            let material = SCNMaterial()
            material.diffuse.contents = Palette.structure.withAlphaComponent(0.16)
            material.emission.contents = Palette.structure.withAlphaComponent(0.08)
            material.lightingModel = .constant
            material.writesToDepthBuffer = false
            bar.materials = [material]

            let node = SCNNode(geometry: bar)
            node.position = SCNVector3(cos(angle) * length / 2, CGFloat(0), sin(angle) * length / 2)
            node.eulerAngles = SCNVector3(CGFloat.pi / 2, CGFloat(0), -angle + CGFloat.pi / 2)
            floor.addChildNode(node)
        }

        world.addChildNode(floor)
    }

    @objc private func refreshTapped() { onRefresh() }

    // MARK: content

    private func rebuild() {
        coreNode.removeFromParentNode()
        eventField.childNodes.forEach { $0.removeFromParentNode() }
        ringNode.childNodes.forEach { $0.removeFromParentNode() }

        buildCore()
        buildRing()
        buildInflow()
        buildUplink()
        buildEventField()
        updateHUD()
    }

    /// The host, drawn as the thing it is.
    ///
    /// A glowing sphere is a logo. This is a rack: a dark metal chassis with
    /// units in it, vents, and status lamps on the front. Two decisions do all
    /// the work of not looking like plastic. The body is metal — high
    /// metalness, low roughness, almost no diffuse colour — so it takes its
    /// appearance from what is around it rather than from a bright fill. And
    /// nothing on it is coloured except the lamps, which are pure emission and
    /// are the only things allowed to bloom.
    ///
    /// The top lamp on each unit carries the agent's overall state, because it
    /// is the one light on a real rack anybody actually looks at.
    private func buildCore() {
        let health = snapshot.failure == nil ? snapshot.overall : .unknown
        let node = SCNNode()

        let units: Int = 5
        let unitHeight: CGFloat = 0.68
        let unitGap: CGFloat = 0.08
        let width: CGFloat = 3.6
        let depth: CGFloat = 2.6
        let stack: CGFloat = CGFloat(units) * (unitHeight + unitGap)

        let shell = SCNBox(width: width, height: stack + 0.34, length: depth, chamferRadius: 0.05)
        let shellMaterial = SCNMaterial()
        shellMaterial.lightingModel = .physicallyBased
        shellMaterial.diffuse.contents = NSColor(calibratedWhite: 0.16, alpha: 1)
        shellMaterial.metalness.contents = 0.72
        shellMaterial.roughness.contents = 0.28
        shell.materials = [shellMaterial]
        node.addChildNode(SCNNode(geometry: shell))

        for index in 0 ..< units {
            let offset: CGFloat = CGFloat(index) * (unitHeight + unitGap)
            let y: CGFloat = stack / 2 - offset - unitHeight / 2 - 0.04

            let face = SCNBox(width: width - 0.10, height: unitHeight, length: 0.07, chamferRadius: 0.012)
            let faceMaterial = SCNMaterial()
            faceMaterial.lightingModel = .physicallyBased
            faceMaterial.diffuse.contents = NSColor(calibratedWhite: 0.22, alpha: 1)
            faceMaterial.metalness.contents = 0.65
            faceMaterial.roughness.contents = 0.38
            face.materials = [faceMaterial]

            let faceNode = SCNNode(geometry: face)
            faceNode.position = SCNVector3(CGFloat(0), y, depth / 2 + 0.02)
            node.addChildNode(faceNode)

            // Vent slots: cut in as darker inset bars rather than modelled as
            // holes, which would cost geometry nothing here can see.
            for slot in 0 ..< 9 {
                let slotBar = SCNBox(width: 0.11, height: unitHeight * 0.42, length: 0.02, chamferRadius: 0.004)
                let slotMaterial = SCNMaterial()
                slotMaterial.lightingModel = .physicallyBased
                slotMaterial.diffuse.contents = NSColor(calibratedWhite: 0.035, alpha: 1)
                slotMaterial.metalness.contents = 0.6
                slotMaterial.roughness.contents = 0.9
                slotBar.materials = [slotMaterial]

                let bar = SCNNode(geometry: slotBar)
                let slotX: CGFloat = -0.62 + CGFloat(slot) * 0.155
                bar.position = SCNVector3(slotX, y, depth / 2 + 0.06)
                node.addChildNode(bar)
            }

            // Lamps. The first unit carries the overall verdict; the rest are
            // activity, dim and cyan, so the verdict lamp is the only coloured
            // thing on the machine.
            let lampColour: NSColor = index == 0 ? health.color : Palette.quiet
            let lampCount: Int = index == 0 ? 2 : 3

            for lamp in 0 ..< lampCount {
                let bulb = SCNSphere(radius: 0.045)
                bulb.segmentCount = 10
                let bulbMaterial = SCNMaterial()
                bulbMaterial.diffuse.contents = lampColour
                bulbMaterial.emission.contents = lampColour
                bulbMaterial.lightingModel = .constant
                bulbMaterial.writesToDepthBuffer = false
                bulb.materials = [bulbMaterial]

                let bulbNode = SCNNode(geometry: bulb)
                let lampX: CGFloat = 1.14 + CGFloat(lamp) * 0.14
                bulbNode.position = SCNVector3(lampX, y, depth / 2 + 0.08)

                // Activity lamps flicker on their own phase. The verdict lamp
                // holds steady: a status light that blinks reads as a fault
                // even when it is green.
                if index != 0 {
                    let phase: Double = Double((index * 3 + lamp) % 5) * 0.37
                    bulbNode.runAction(.sequence([
                        .wait(duration: phase),
                        .repeatForever(.sequence([
                            .fadeOpacity(to: 0.15, duration: 0.5 + Double(lamp) * 0.2),
                            .fadeOpacity(to: 1.0, duration: 0.4 + Double(index) * 0.15),
                        ])),
                    ]))
                }

                node.addChildNode(bulbNode)
            }
        }

        // A faint cage around the rack, at the radius the old sphere occupied,
        // so the event shell still has something to sit against.
        let cage = SCNSphere(radius: 2.7)
        cage.segmentCount = 16
        let cageMaterial = SCNMaterial()
        cageMaterial.diffuse.contents = health.color.withAlphaComponent(0.09)
        cageMaterial.emission.contents = health.color.withAlphaComponent(0.05)
        cageMaterial.fillMode = .lines
        cageMaterial.lightingModel = .constant
        cageMaterial.writesToDepthBuffer = false
        cage.materials = [cageMaterial]

        let cageNode = SCNNode(geometry: cage)
        cageNode.runAction(.repeatForever(
            .rotateBy(x: CGFloat(0), y: CGFloat.pi * 2, z: CGFloat(0), duration: 70)
        ))
        node.addChildNode(cageNode)

        // Two inclined rings, the way an instrument draws an axis. They are
        // furniture, so they are dim.
        for (index, tilt) in [CGFloat.pi / 2.6, -CGFloat.pi / 3.4].enumerated() {
            let orbit = SCNTorus(ringRadius: 2.35 + CGFloat(index) * 0.5, pipeRadius: 0.016)
            orbit.ringSegmentCount = 128
            orbit.pipeSegmentCount = 6

            let material = SCNMaterial()
            material.diffuse.contents = health.color.withAlphaComponent(0.42)
            material.emission.contents = health.color.withAlphaComponent(0.30)
            material.lightingModel = .constant
            material.writesToDepthBuffer = false
            orbit.materials = [material]

            let orbitNode = SCNNode(geometry: orbit)
            orbitNode.eulerAngles = SCNVector3(tilt, CGFloat(index) * 0.7, CGFloat(0))
            orbitNode.runAction(.repeatForever(
                .rotateBy(x: CGFloat(0), y: CGFloat.pi * 2, z: CGFloat(0), duration: 30 + Double(index) * 14)
            ))
            node.addChildNode(orbitNode)
        }

        // The rack itself does not pulse. Breathing hardware reads as a
        // rendering effect; the lamps are what is alive here.
        coreNode = node
        world.addChildNode(node)
    }

    /// One slim column per subsystem, standing on the grid.
    private func buildRing() {
        let rows = snapshot.rows
        guard !rows.isEmpty else { return }

        let radius: CGFloat = 12.4

        for (index, row) in rows.enumerated() {
            let fraction: CGFloat = CGFloat(index) / CGFloat(rows.count)
            let angle: CGFloat = fraction * 2 * CGFloat.pi
            let x: CGFloat = radius * cos(angle)
            let z: CGFloat = radius * sin(angle)

            // Every column is the same height. A taller bar for "worse" would
            // invent a ranking the agent never stated.
            let column = SCNCylinder(radius: 0.075, height: 3.4)
            column.radialSegmentCount = 16
            let material = SCNMaterial()
            material.diffuse.contents = row.health.color
            material.emission.contents = row.health.color.withAlphaComponent(0.95)
            material.lightingModel = .constant
            column.materials = [material]

            let node = SCNNode(geometry: column)
            node.position = SCNVector3(x, CGFloat(-3.5), z)
            ringNode.addChildNode(node)

            // A disc at the foot, so the column is standing on the grid rather
            // than hovering above it.
            let pad = SCNTorus(ringRadius: 0.42, pipeRadius: 0.02)
            pad.ringSegmentCount = 48
            let padMaterial = SCNMaterial()
            padMaterial.diffuse.contents = row.health.color.withAlphaComponent(0.7)
            padMaterial.emission.contents = row.health.color.withAlphaComponent(0.55)
            padMaterial.lightingModel = .constant
            padMaterial.writesToDepthBuffer = false
            pad.materials = [padMaterial]

            let padNode = SCNNode(geometry: pad)
            padNode.position = SCNVector3(x, CGFloat(-5.18), z)
            ringNode.addChildNode(padNode)

            let label = labelNode(row.title.uppercased(), color: NSColor(calibratedWhite: 0.80, alpha: 1), size: 0.42)
            label.position = SCNVector3(x, CGFloat(-1.25), z)
            ringNode.addChildNode(label)

            let state = labelNode(row.health.rawValue.uppercased(), color: row.health.color.withAlphaComponent(0.9), size: 0.28)
            state.position = SCNVector3(x, CGFloat(-1.72), z)
            ringNode.addChildNode(state)

            let beam = SCNCylinder(radius: 0.011, height: radius)
            let beamMaterial = SCNMaterial()
            beamMaterial.diffuse.contents = row.health.color.withAlphaComponent(0.30)
            beamMaterial.emission.contents = row.health.color.withAlphaComponent(0.20)
            beamMaterial.lightingModel = .constant
            beamMaterial.writesToDepthBuffer = false
            beam.materials = [beamMaterial]

            let beamNode = SCNNode(geometry: beam)
            beamNode.position = SCNVector3(x / 2, CGFloat(-3.5), z / 2)
            // Aimed, not composed out of Euler angles.
            //
            // A cylinder stands along its own +Y, so pointing one at the core
            // means rotating about two axes at once, and the hand-written pair
            // above was wrong: the beams did not run from column to core, they
            // sliced across the whole scene at arbitrary angles and read as
            // rendering artefacts. look(at:) solves the same problem exactly
            // and cannot be got subtly wrong.
            beamNode.look(
                at: SCNVector3(CGFloat(0), CGFloat(-3.5), CGFloat(0)),
                up: SCNVector3(CGFloat(0), CGFloat(1), CGFloat(0)),
                localFront: SCNVector3(CGFloat(0), CGFloat(1), CGFloat(0))
            )
            ringNode.addChildNode(beamNode)
        }
    }

    /// Every event the sensor is holding, as a distribution over time.
    ///
    /// The first version of this was a shell of one dot per event around the
    /// core. It was accurate and it was unreadable: five hundred points on a
    /// sphere is a texture, not a reading, and it buried the machine it was
    /// supposed to be describing.
    ///
    /// The question the events actually answer is "when", so they are bucketed
    /// by time and stood up as bars on the floor — oldest at the back, newest
    /// at the front. A burst is a spike, a steady drift is a flat run, and the
    /// alerting share is the lit part of each bar rather than a separate
    /// colour of dot mixed in among the rest. Every event is still counted;
    /// none of them is drawn twice.
    private func buildEventField() {
        guard !events.isEmpty else { return }

        let buckets: Int = 36
        var totals = [Int](repeating: 0, count: buckets)
        var alerting = [Int](repeating: 0, count: buckets)

        // events arrive newest first
        let newest: Date = events.first?.at ?? Date()
        let oldest: Date = events.last?.at ?? newest
        let span: Double = max(1, newest.timeIntervalSince(oldest))

        for event in events {
            let age: Double = newest.timeIntervalSince(event.at)
            let slot: Int = min(buckets - 1, max(0, Int((age / span) * Double(buckets - 1))))
            totals[slot] += 1

            if event.isAlert {
                alerting[slot] += 1
            }
        }

        let peak: Int = max(1, totals.max() ?? 1)
        let radius: CGFloat = 5.4
        let tallest: CGFloat = 3.2

        for slot in 0 ..< buckets {
            let fraction: CGFloat = CGFloat(slot) / CGFloat(buckets)
            let angle: CGFloat = fraction * 2 * CGFloat.pi
            let x: CGFloat = radius * cos(angle)
            let z: CGFloat = radius * sin(angle)

            // A bucket with nothing in it still gets a mark.
            //
            // Skipping them left a gap in the ring wherever the sensor had
            // been down, and a gap reads as "not drawn" rather than as
            // "measured, and it was none" — which is the same confusion
            // between absent and unknown that the rest of this console works
            // to avoid. The tick is the floor of the chart, so a quiet stretch
            // is visibly quiet instead of visibly missing.
            guard totals[slot] > 0 else {
                let tick = SCNBox(width: 0.16, height: 0.03, length: 0.16, chamferRadius: 0.01)
                let tickMaterial = SCNMaterial()
                tickMaterial.diffuse.contents = Palette.structure.withAlphaComponent(0.30)
                tickMaterial.emission.contents = Palette.structure.withAlphaComponent(0.18)
                tickMaterial.lightingModel = .constant
                tick.materials = [tickMaterial]

                let tickNode = SCNNode(geometry: tick)
                tickNode.position = SCNVector3(x, CGFloat(-5.19), z)
                eventField.addChildNode(tickNode)
                continue
            }

            let share: CGFloat = CGFloat(totals[slot]) / CGFloat(peak)
            let height: CGFloat = 0.12 + share * tallest

            let alertShare: CGFloat = CGFloat(alerting[slot]) / CGFloat(totals[slot])
            let colour: NSColor = alertShare > 0.5 ? Palette.alert : Palette.quiet

            let bar = SCNBox(width: 0.16, height: height, length: 0.16, chamferRadius: 0.02)
            let material = SCNMaterial()
            material.diffuse.contents = colour.withAlphaComponent(0.75)
            material.emission.contents = colour.withAlphaComponent(0.55 + alertShare * 0.4)
            material.lightingModel = .constant
            bar.materials = [material]

            let node = SCNNode(geometry: bar)
            node.position = SCNVector3(x, CGFloat(-5.2) + height / 2, z)
            eventField.addChildNode(node)
        }
    }

    /// Telemetry arriving at the agent.
    ///
    /// The counterpart to buildUplink(): the sensors feed the rack, the rack
    /// feeds the Hub, and between them that is the whole path a piece of
    /// evidence takes on this host.
    ///
    /// Only a subsystem that is actually up sends anything, and the endpoint
    /// sensor only sends if it has spooled something. A console that animates
    /// a dead sensor delivering telemetry would be inventing the exact fact
    /// this product exists to report — and it would look completely
    /// convincing, which is what makes it worth spelling out.
    private func buildInflow() {
        let radius: CGFloat = 8.2
        let sources: Set<String> = ["Endpoint sensor", "Suricata"]

        for (index, row) in snapshot.rows.enumerated() {
            guard sources.contains(row.title) else { continue }
            guard row.health == .ok || row.health == .warming else { continue }

            if row.title == "Endpoint sensor", events.isEmpty { continue }

            let fraction: CGFloat = CGFloat(index) / CGFloat(snapshot.rows.count)
            let angle: CGFloat = fraction * 2 * CGFloat.pi
            let origin = SCNVector3(radius * cos(angle), CGFloat(-1.8), radius * sin(angle))
            let core = SCNVector3(CGFloat(0), CGFloat(0), CGFloat(0))

            // Three per source, staggered. The count is a rhythm, not a rate:
            // the agent does not report a per-second figure, so the console
            // must not appear to.
            let packets: Int = 3
            let flight: Double = 2.1

            for slot in 0 ..< packets {
                let packet = SCNSphere(radius: 0.06)
                packet.segmentCount = 8
                let material = SCNMaterial()
                material.diffuse.contents = row.health.color
                material.emission.contents = row.health.color.withAlphaComponent(0.85)
                material.lightingModel = .constant
                material.writesToDepthBuffer = false
                packet.materials = [material]

                let node = SCNNode(geometry: packet)
                node.position = origin
                node.opacity = 0

                let stagger: Double = (flight / Double(packets)) * Double(slot)

                node.runAction(.sequence([
                    .wait(duration: stagger),
                    .repeatForever(.sequence([
                        .fadeIn(duration: 0.16),
                        .move(to: core, duration: flight),
                        .fadeOut(duration: 0.2),
                        .move(to: origin, duration: 0),
                    ])),
                ]))

                ringNode.addChildNode(node)
            }
        }
    }

    /// Traffic going up the wire to the Hub.
    ///
    /// Driven by the agent's own delivery record rather than by the fact that
    /// a console looks better with something moving in it. If nothing has been
    /// delivered and nothing is queued, nothing flies: a scene that animates
    /// traffic on a dead link is lying in the most convincing way available to
    /// it, and this is the one view where that would be easiest to get away
    /// with.
    ///
    /// The packets carry the Hub's own colour, so a link that is backing off
    /// sends amber up the same wire rather than green.
    private func buildUplink() {
        guard let hubIndex = snapshot.rows.firstIndex(where: { $0.title == "Hub" }) else { return }

        guard let hub = snapshot.raw["hub"] as? [String: Any],
              let record = hub["transmission"] as? [String: Any],
              (record["observed"] as? Bool) == true
        else { return }

        let delivered: Int = AgentReader.int(record["delivered"]) ?? 0
        let failures: Int = AgentReader.int(record["failures"]) ?? 0
        let queued: Int = events.filter { $0.deliver && !$0.sent }.count

        guard delivered > 0 || failures > 0 || queued > 0 else { return }

        let health = snapshot.rows[hubIndex].health
        let radius: CGFloat = 8.2
        let fraction: CGFloat = CGFloat(hubIndex) / CGFloat(snapshot.rows.count)
        let angle: CGFloat = fraction * 2 * CGFloat.pi
        let target = SCNVector3(radius * cos(angle), CGFloat(-1.9), radius * sin(angle))

        // A thin standing line the packets run along, so the route is legible
        // even between them.
        let wire = SCNCylinder(radius: 0.014, height: radius)
        let wireMaterial = SCNMaterial()
        wireMaterial.diffuse.contents = health.color.withAlphaComponent(0.30)
        wireMaterial.emission.contents = health.color.withAlphaComponent(0.28)
        wireMaterial.lightingModel = .constant
        wireMaterial.writesToDepthBuffer = false
        wire.materials = [wireMaterial]

        let wireNode = SCNNode(geometry: wire)
        wireNode.position = SCNVector3(target.x / 2, target.y / 2, target.z / 2)
        wireNode.look(
            at: target,
            up: SCNVector3(CGFloat(0), CGFloat(1), CGFloat(0)),
            localFront: SCNVector3(CGFloat(0), CGFloat(1), CGFloat(0))
        )
        ringNode.addChildNode(wireNode)

        // Four in flight, staggered. Enough to read as a stream, few enough
        // that the count is not mistaken for a measurement of throughput.
        let packets: Int = 4
        let flight: Double = failures > 0 ? 2.6 : 1.7

        for index in 0 ..< packets {
            let packet = SCNSphere(radius: 0.075)
            packet.segmentCount = 10
            let material = SCNMaterial()
            material.diffuse.contents = health.color
            material.emission.contents = health.color.withAlphaComponent(0.9)
            material.lightingModel = .constant
            material.writesToDepthBuffer = false
            packet.materials = [material]

            let node = SCNNode(geometry: packet)
            node.position = SCNVector3(CGFloat(0), CGFloat(0), CGFloat(0))
            node.opacity = 0

            let stagger: Double = (flight / Double(packets)) * Double(index)

            node.runAction(.sequence([
                .wait(duration: stagger),
                .repeatForever(.sequence([
                    .group([.fadeIn(duration: 0.18), .scale(to: 1.0, duration: 0.18)]),
                    .move(to: target, duration: flight),
                    .fadeOut(duration: 0.22),
                    .move(to: SCNVector3(CGFloat(0), CGFloat(0), CGFloat(0)), duration: 0),
                ])),
            ]))

            ringNode.addChildNode(node)
        }
    }

    private func updateHUD() {
        let health = snapshot.failure == nil ? snapshot.overall : .unknown
        headline.stringValue = health.rawValue.uppercased()
        headline.textColor = health.color

        subhead.stringValue = [snapshot.hostName, snapshot.hostOS]
            .filter { !$0.isEmpty }
            .joined(separator: "  ·  ")

        let alerts: Int = events.filter { $0.isAlert }.count
        let queued: Int = events.filter { $0.deliver && !$0.sent }.count
        let quiet: Int = events.count - alerts

        if events.isEmpty {
            legend.stringValue = "No events spooled yet"
        } else {
            var parts: [String] = []
            parts.append("● " + String(alerts) + " alerting")
            parts.append("● " + String(quiet) + " retro-hunt")
            parts.append("↑ " + String(queued) + " queued")
            legend.stringValue = parts.joined(separator: "    ")
        }

        transmission.stringValue = hubLine()
        transmission.textColor = hubTroubled()
            ? NSColor.systemYellow.withAlphaComponent(0.9)
            : NSColor(calibratedWhite: 0.52, alpha: 1)

        footnote.stringValue = footerLine()
    }

    /// What the Hub link has actually been doing.
    ///
    /// The instantaneous state says "ok" between failures, which on a link
    /// that fails and recovers all day is true every time it is asked and
    /// useless. The agent's rolling record is what makes an unreliable link
    /// visible, so it is what this line shows.
    private func hubLine() -> String {
        guard let hub = snapshot.raw["hub"] as? [String: Any] else { return "" }

        let host = hub["url"] as? String ?? "not configured"

        guard let record = hub["transmission"] as? [String: Any],
              (record["observed"] as? Bool) == true
        else { return "HUB  " + host + "  ·  no delivery attempted yet" }

        let attempts = AgentReader.int(record["attempts"]) ?? 0
        let failures = AgentReader.int(record["failures"]) ?? 0
        let delivered = AgentReader.int(record["delivered"]) ?? 0

        var line = "HUB  " + host + "  ·  24h "
        line += String(attempts - failures) + "/" + String(attempts) + " ok"
        line += "  ·  " + AgentReader.format(delivered) + " delivered"

        if failures > 0 {
            line += "  ·  " + String(failures) + " failed"

            if let reason = record["last_error"] as? String, !reason.isEmpty {
                line += " (" + reason + ")"
            }
        }

        return line
    }

    private func hubTroubled() -> Bool {
        guard let hub = snapshot.raw["hub"] as? [String: Any],
              let record = hub["transmission"] as? [String: Any]
        else { return false }

        return (AgentReader.int(record["failures"]) ?? 0) > 0
    }

    /// Says what is not on screen.
    ///
    /// A scene that draws four thousand of half a million points and reports
    /// only the four thousand is the same failure as a status that paints
    /// unknown green: it reads as complete when it is a sample.
    private func footerLine() -> String {
        let hint: String = "drag to orbit, scroll to zoom"

        guard !events.isEmpty else { return hint }

        var line = String(events.count)

        if feed.truncated, let held = feed.held {
            line += " of " + AgentReader.format(held) + " held"
        } else {
            line += " events"
        }

        if let oldest = events.last?.at, let newest = events.first?.at {
            let span: Int = Int(newest.timeIntervalSince(oldest) / 60)
            line += "  ·  spanning " + String(span) + " min"
        }

        return line + "  ·  " + hint
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
