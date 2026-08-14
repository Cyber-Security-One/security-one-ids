<?php

namespace App\Services\Identity;

use App\Services\EdrAlertFactory;
use App\Services\EdrEventSpool;
use App\Services\LogCursor;
use App\Services\Quality\EdrRuleGovernor;
use Illuminate\Support\Facades\Log;

/**
 * Collects authentication events from the host's auth log.
 *
 * Stolen credentials are the most common way into a machine, and the existing
 * agent could only see them as unstructured log text — enough to count failed
 * logins, not enough to notice that one source was trying forty accounts, or
 * that a success arrived immediately after a run of failures.
 *
 * Sources, in the order they are actually available:
 *
 *  - `/var/log/auth.log` or `/var/log/secure`. Present on essentially every
 *    Linux host and the only source that carries SSH authentication results.
 *  - utmp/wtmp, via osquery's `last` table, is deliberately not used. It does
 *    not exist at all on minimal and container hosts — including the one this
 *    was developed on, where both `last` and `logged_in_users` return nothing
 *    — so building on it would produce an agent that silently sees no logins
 *    on exactly the hosts most likely to be running in a container.
 *
 * Events flow into the same spool and through the same governance as process
 * and file events, so the learning window, rule staging and false-positive
 * accounting all apply without special cases.
 */
class IdentityCollector
{
    /** Auth logs are text and small; a smaller budget than the sensor log. */
    private const MAX_BYTES_PER_CYCLE = 2 * 1024 * 1024;

    private const MAX_ALERTS_PER_CYCLE = 50;

    private AuthLogParser $parser;
    private EdrEventSpool $spool;
    private EdrAlertFactory $factory;
    private EdrRuleGovernor $governor;
    private ?LogCursor $cursor = null;

    public function __construct(
        AuthLogParser $parser,
        EdrEventSpool $spool,
        EdrAlertFactory $factory,
        EdrRuleGovernor $governor
    ) {
        $this->parser = $parser;
        $this->spool = $spool;
        $this->factory = $factory;
        $this->governor = $governor;
    }

    /**
     * @return array{alerts: array<int, array>, stats: array}
     */
    public function collect(array $options = []): array
    {
        $empty = [
            'alerts' => [],
            'stats' => ['events' => 0, 'alerts' => 0, 'suppressed' => 0, 'spooled' => 0, 'by_rule' => [], 'log' => null],
        ];

        $logPath = $this->resolveLogPath();

        if ($logPath === null) {
            Log::debug('[EDR identity] No readable authentication log on this host');

            return $empty;
        }

        $this->governor->ensureBaselineStarted();

        $read = $this->cursor()->read($logPath);
        $lines = $read['lines'];

        if ($lines === []) {
            $this->cursor()->commit($read['cursor']);

            return array_merge($empty, ['stats' => array_merge($empty['stats'], ['log' => $logPath])]);
        }

        $events = [];

        foreach ($lines as $line) {
            $event = $this->parser->parse($line);

            if ($event !== null) {
                $events[] = $event;
            }
        }

        if ($events === []) {
            // The window held nothing about authentication. Nothing to store,
            // so the cursor can move.
            $this->cursor()->commit($read['cursor']);

            return array_merge($empty, ['stats' => array_merge($empty['stats'], ['log' => $logPath])]);
        }

        // The window rules need this cycle's events counted — a burst of forty
        // failures usually arrives in one batch, and history that only knew
        // what was already committed would see the fortieth attempt as the
        // first. Rather than write the batch, evaluate, then write it again
        // with its findings, the batch is handed to the history provider and
        // the spool is written once, afterwards, with everything attached.
        $rules = new IdentityRuleEngine(new SpoolIdentityHistory($this->spool, $events));

        $alerts = [];
        $byRule = [];
        $suppressed = 0;
        $findingsByEvent = [];
        $deliverable = [];

        foreach ($events as $index => $event) {
            $findings = $rules->evaluate($event);

            if ($findings === []) {
                continue;
            }

            $emitted = [];

            foreach ($findings as $finding) {
                $decision = $this->governor->assess($finding, $event, $options);
                $this->governor->record($decision, $finding, $event, $options);

                $byRule[$finding['rule']] = ($byRule[$finding['rule']] ?? 0) + 1;

                if ($decision['emit']) {
                    $finding['stage'] = $decision['stage'];
                    $finding['allow_response'] = $decision['allow_response'];
                    $emitted[] = $finding;
                } else {
                    $suppressed++;
                }
            }

            // Stored whether emitted or not: a suppressed identity finding is
            // the raw material for tuning, exactly as elsewhere.
            $findingsByEvent[$index] = $findings;
            $deliverable[$index] = $emitted !== [];

            if ($emitted !== [] && count($alerts) < self::MAX_ALERTS_PER_CYCLE) {
                $alerts[] = ['event' => $event, 'findings' => $emitted];
            }
        }

        $alerts = $this->collapseRepeats($alerts);

        $spooled = $this->spool->store($events, $findingsByEvent, $deliverable);

        // Advance only once the batch is durably stored, so a failed write
        // costs a re-read rather than a gap in the authentication record.
        if ($spooled > 0) {
            $this->cursor()->commit($read['cursor']);
        } else {
            Log::warning('[EDR identity] Spool write failed, holding cursor to re-read next cycle', [
                'events' => count($events),
            ]);
        }

        arsort($byRule);

        return [
            'alerts' => array_map(
                fn (array $hit): array => $this->factory->fromEvent($hit['event'], $hit['findings']),
                $alerts
            ),
            'stats' => [
                'events' => count($events),
                'alerts' => count($alerts),
                'suppressed' => $suppressed,
                'spooled' => $spooled,
                'by_rule' => $byRule,
                'log' => $logPath,
            ],
        ];
    }

    /**
     * A brute-force burst produces one finding per failure once the threshold
     * is crossed, so forty attempts would raise thirty-three identical
     * alerts. The window rules describe a situation, and a situation is one
     * alert.
     *
     * @param  array<int, array{event:array,findings:array}> $hits
     * @return array<int, array{event:array,findings:array}>
     */
    private function collapseRepeats(array $hits): array
    {
        $seen = [];
        $kept = [];

        foreach ($hits as $hit) {
            $event = $hit['event'];

            $remaining = array_filter(
                $hit['findings'],
                static function (array $finding) use (&$seen, $event): bool {
                    // Keyed on what the rule is actually about: the source for
                    // the window rules, the account for the rest.
                    $subject = $event['source_ip'] ?? $event['actor'] ?? $event['username'] ?? '';
                    $key = ($finding['rule'] ?? '') . '|' . $subject;

                    if (isset($seen[$key])) {
                        return false;
                    }

                    $seen[$key] = true;

                    return true;
                }
            );

            if ($remaining !== []) {
                $hit['findings'] = array_values($remaining);
                $kept[] = $hit;
            }
        }

        return $kept;
    }

    public function resolveLogPath(): ?string
    {
        foreach (AuthLogParser::candidateLogPaths() as $candidate) {
            if (is_file($candidate) && is_readable($candidate)) {
                return $candidate;
            }
        }

        return null;
    }

    private function cursor(): LogCursor
    {
        return $this->cursor ??= new LogCursor(
            storage_path('app/edr_authlog_position.json'),
            self::MAX_BYTES_PER_CYCLE
        );
    }
}
