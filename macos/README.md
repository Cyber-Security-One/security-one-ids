# Security One — macOS menu bar console

A small status item that shows what the agent on this machine currently knows
about itself: the endpoint sensor, the behaviour correlator, Suricata, ClamAV,
and the Hub connection — plus the number nobody can guess from the outside,
which is how far back the event spool actually reaches.

```
● Security One Agent
  gx10-dc8a · Darwin 24.6.0 arm64

  ●  Endpoint sensor  endpointsecurity
  ●  Correlator       warming 34% · 4.8/14 days
  ●  Suricata         7.0.10 · 41,203 rules
  ●  ClamAV           1.4.3
  ●  Hub              waf.cybersecureone.com

  History held
    process   494,168 · 1.9h
    network     5,832 · 1.0h
    identity      630 · 67.4h

  Updated just now
  Open full report
  Refresh now
```

## Build

Needs the Command Line Tools (`xcode-select --install`) and nothing else — no
Xcode project, no package manager, one Swift file against AppKit.

First make sure the checkout has this directory in it. The installer leaves the
agent on a shallow, non-tracking branch, so plain `git pull` reports divergent
branches and fetches nothing:

```bash
cd /opt/security-one-ids
sudo git fetch --depth 1 origin feat/edr-endpoint-sensor
sudo git checkout -B feat/edr-endpoint-sensor FETCH_HEAD
```

Then build **as yourself, not with sudo**:

```bash
cd /opt/security-one-ids/macos/SecurityOneMenuBar
./build.sh install
```

The agent directory is root-owned, so sudo is the natural reflex here and it is
the wrong one: a menu bar app launched by root belongs to root's GUI session,
so it would build, install, report success, and never appear. The script
refuses to run as root, builds into `~/Library/Caches/`, and asks for a
password only if `/Applications` actually needs one.

`./build.sh` without `install` builds the bundle without installing it. The
bundle is ad-hoc signed, which is what lets it run on Apple Silicon at all; it
is not a distribution signature, so the first launch may still need an approval
in **System Settings → Privacy & Security**.

To start it at login: **System Settings → General → Login Items → +**, and pick
`/Applications/SecurityOne.app`.

## How it gets its numbers

It runs `php artisan ids:status --json` in `/opt/security-one-ids` every 30
seconds, and again whenever the menu is opened.

It deliberately has no opinion of its own about what "healthy" means. Every
state, every threshold and every piece of remediation advice comes from that
one command, because a console that decides for itself is a second
implementation of the same judgement — and the day the two disagree, nothing
tells you which one is wrong. The console's whole job is to render.

Three rules it inherits from the snapshot:

- **Unknown is never painted green.** This app runs unprivileged, and the Hub
  credentials live in a root-only file, so there are things it genuinely cannot
  determine. Those show yellow with the reason, not green.
- **Warming is not a fault.** The correlator is silent by design for its first
  fortnight while it learns what this host normally does. It shows progress, in
  teal. A red dot for two weeks teaches people to ignore red.
- **Retention is reported per event class, never averaged.** The classes have
  separate ceilings, so a single figure across the spool reports the long tail
  of a small class as though it were the window everything has. On the host
  above that would read "67 hours" while the process telemetry an investigation
  would actually query reached back under two.

If the agent cannot be reached, the item goes yellow and the menu says which
part failed — which PHP it looked for, or which path was missing — rather than
a bare "unavailable" that sends you looking in the wrong place.

## Requirements

- macOS 11 or later
- The agent installed at `/opt/security-one-ids`
- PHP at `/opt/homebrew/bin/php`, `/usr/local/bin/php`, or `/usr/bin/php`

`Open full report` drives Terminal via AppleScript, so the first use asks for
Automation permission. Declining it costs only that one menu item.

## Sensor note

The full-fidelity backend on macOS is EndpointSecurity, and osquery can only
use it once it has Full Disk Access:

**System Settings → Privacy & Security → Full Disk Access → +** →
`/opt/osquery/lib/osquery.app/Contents/MacOS/osqueryd`

Until that is granted the sensor reports no backend, and the menu says so along
with that instruction. Confirm with:

```bash
php artisan ids:sync-edr --status   # expect: backend: endpointsecurity
```

## If the icon does not appear

The app is a background agent with no window, so "running" and "visible" are
separate things and neither implies the other. Check which one you have:

```bash
pgrep -lf SecurityOne
```

A PID means it is running and the icon is the problem — most often a crowded
menu bar, or a notched display where items to the left of the notch are hidden.
Quitting a few other menu bar items is the quickest test.

No PID means it exited. Run the binary in the foreground to see why:

```bash
/Applications/SecurityOne.app/Contents/MacOS/SecurityOne
```

## Status

Written on Linux with no macOS host to test on, so the first build was done on
a real Mac. It compiled clean, ran, and showed nothing: the status item was
being created as a property initialiser, which runs before `app.run()` and
therefore before there is a menu bar to put it in. Allocated, retained, every
call succeeding, permanently invisible — and a live process with no icon looks
identical from the outside to an app that failed to launch. It is now created
in `applicationDidFinishLaunching`, which is the only point at which that is
guaranteed to work.

Worth stating because it is the pattern behind most of this branch's defects:
the failure was silent, the component reported success at every step, and the
only thing that revealed it was running the real thing on a real machine.
