# Security One — Windows endpoint sensor

The EDR agent's third platform. Process telemetry comes from ETW through
osquery's `process_etw_events` publisher, the same way it comes from eBPF on
Linux and EndpointSecurity on macOS, and feeds the identical rule engine and
correlator.

## Install

From an **elevated** PowerShell, inside the checkout:

```powershell
.\install\install.ps1
```

It installs osquery if it is missing, writes a floor configuration, registers
`SecurityOneSensor` as a LocalSystem service, and starts it. Running it again
repairs or upgrades — it is idempotent.

```powershell
.\install\install.ps1 -StatusOnly     # no changes, just report
.\install\install.ps1 -Uninstall      # remove the service, leave the data
```

Then confirm from the agent's side:

```powershell
php artisan ids:sync-edr --status     # expect backend: etw
php artisan ids:status                # every subsystem in one view
```

### Requirements

- Windows 10 / Server 2016 or later
- **Administrator.** ETW's kernel process provider cannot be subscribed to
  from anything less. A sensor installed unelevated starts cleanly, reports
  healthy, and collects nothing.
- osquery **5.5 or later** — `process_etw_events` did not exist before it. On
  an older build the table is absent rather than empty, which makes osqueryd
  log an error every interval and produce no rows: a broken-looking sensor for
  a version-shaped reason.

## Why a second osquery service

The MSI installs osquery's own `osqueryd` service. This installer does not
touch it. A customer may already run osquery for inventory or compliance, and
taking over their daemon's config, database and schedule would be hostile —
the same reason the Linux installer refuses to commandeer a running `auditd`.
`SecurityOneSensor` is a separate service with its own everything.

## The paths have to match

Four paths are shared between the installer and `OsqueryEngine`, and they are
not a matter of preference:

| | |
|---|---|
| config | `<checkout>\storage\app\osquery\osquery.conf` |
| database | `<checkout>\storage\app\osquery\db` |
| logs | `C:\ProgramData\SecurityOne\osquery` |
| service | `SecurityOneSensor` |

The config path is the one that bites. The agent rewrites that file every time
the Hub pushes new options. Point the service somewhere else and both halves
work perfectly against different files: every option is received, applied,
saved — and ignored, while the sensor runs forever on the floor config the
installer wrote. Nothing reports a fault.

`install.ps1` derives the checkout from its own location, so it stays correct
if the agent is not in the default directory. Pass `-InstallDir` if you run it
from somewhere else.

## What Windows cannot see

Stated here because a detection that silently never fires still counts itself
as coverage, and that is the failure this whole branch has spent its time
hunting. Both are reported as values (`containerVisibility()`,
`persistenceVisibility()`) rather than left as absent branches.

**No outbound connection events.** osquery's Windows ETW publisher covers
process start and stop. There is no per-connection event stream to subscribe
to, so `sensorTables()` returns `socket => null` — deliberately, rather than
scheduling a query against a table that does not exist. `listening_ports` is
still polled, so a *new listener* is visible; an outbound connection is not.
macOS has the same gap for the same reason.

**Registry persistence is invisible.** Run keys, service definitions and WMI
event subscriptions are the larger half of persistence on Windows and none of
them is a file, so the file event stream cannot see them.
`persistenceVisibility()` returns `files_only`. What *is* watched: scheduled
task definitions under `C:\Windows\System32\Tasks`, the Start Menu startup
folders, the hosts file, and Group Policy. The PERSIST kill-chain class exists
on all three platforms and would otherwise look equally covered on all three.

**No container id.** Docker Desktop runs Linux containers in a VM the host
sensor cannot see into, and Windows process-isolated containers do not surface
an id on the ETW process stream. `containerVisibility()` returns
`not_observable`.

## Things that differ from the Unix platforms

**Paths are folded before anything compares them.** Windows paths are
backslash-separated and case-insensitive; every prefix list in the facet
extractor is forward-slash and lowercase. `foldPath()` lowercases and turns the
separators round on Windows only. Without it, no prefix matches any path, every
executable lands in the `other` bucket, and the image facet collapses to a
single value for the life of the host — with no error anywhere.

**The event clock is already wall clock.** ETW timestamps do not need
anchoring, unlike Linux's boot-relative `ntime`. `eventClock()` returns
`CLOCK_WALL` for this; it used to be a boolean and a boolean could only say
"anchor" or "give up". Treating Windows as "give up" would stamp every event
with its batch's flush time — measured on the Linux host at 8,820 exec rows
under a single timestamp, which broke the correlator's ordering bonus by making
thousands of unrelated events look simultaneous.

**There is no uid.** Identity is a SID, and the sensor names the account on
every event. `users()` returns an empty map on purpose and
`usernameIsReported()` says why, so a caller can tell "nothing to look up" from
"the lookup failed".

**IIS application pools each get their own identity.** `IIS APPPOOL\<name>` is
matched by prefix, not by a fixed list — a list can only ever catch the default
pool, and every site running under its own would lose the webshell detection
while the rule still reported itself enabled.

**No pidfile.** `--pidfile` and `--daemonize` are POSIX-only osquery flags.
`isRunning()` asks the service control manager instead, which also
distinguishes *stopped* from *not installed* — two states that need different
commands from whoever is fixing it.

## Troubleshooting

**Service runs, telemetry stays empty.** The one failure here that looks
exactly like success. `-StatusOnly` checks for it specifically: a results log
of zero bytes with the service running means the ETW publisher did not attach.
Usually the service is not LocalSystem, or osquery predates 5.5.

**`ids:sync-edr --status` says no backend.** Either osquery is missing, or its
version is below 5.5. Both are reported by name rather than as a generic
failure.

**Options from the Hub have no effect.** Check that the service's
`--config_path` is the checkout's `storage\app\osquery\osquery.conf` and not
somewhere under ProgramData:

```powershell
(Get-CimInstance Win32_Service -Filter "Name='SecurityOneSensor'").PathName
```

## Status

**None of this has run on Windows.** The platform vocabulary is exercised from
Linux by constructing the Windows profile and running the real matching logic
against it, which rules out a Linux fact silently applied to Windows. It rules
out nothing about whether the publisher attaches, whether the service starts,
or whether osquery spells its columns the way this code expects.

The macOS port is the precedent worth taking seriously: six defects were found
by running it on a real Mac and zero were found by reading the code — including
one where the process was alive, every API call succeeded, and the interface
had simply never been created.
