<?php

namespace App\Services\Response;

use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Process;

/**
 * Cuts a host off from the network while keeping the leash we need to let it
 * back on.
 *
 * This is the most dangerous action the product performs. Every other
 * response can be undone by the next command from the Hub; this one can
 * destroy the channel that command would arrive on. Three properties keep it
 * survivable:
 *
 * **Resolve before you cut.** The Hub's addresses are resolved and pinned
 * into the allowlist *before* any rule is inserted. If we cannot work out how
 * to reach the Hub, we refuse to isolate at all — an unreachable agent is not
 * a contained host, it is a lost one.
 *
 * **Prove the leash still works.** Immediately after the rules go in we
 * confirm the Hub is still reachable. If it is not, the isolation is rolled
 * back on the spot rather than left in place for someone to discover.
 *
 * **Never isolate without a deadline.** The caller must supply an expiry. The
 * rollback timer is the backstop for every failure this class cannot detect
 * itself, so an isolation with no deadline is not offered.
 *
 * Rules live in dedicated chains, so removing them never touches whatever
 * firewall policy the customer already had.
 */
class NetworkContainment
{
    public const CHAIN_OUT = 'SECONE_EDR_OUT';
    public const CHAIN_IN = 'SECONE_EDR_IN';

    private string $iptables;

    /**
     * @param string|null $iptablesCommand Override the iptables invocation.
     *                                     Exists so this class can be
     *                                     exercised for real inside a network
     *                                     namespace — the only way to test a
     *                                     capability whose failure mode is
     *                                     "the host is now unreachable"
     *                                     without risking a live machine.
     *                                     Never sourced from Hub input.
     */
    public function __construct(?string $iptablesCommand = null)
    {
        $this->iptables = $iptablesCommand ?? 'iptables';
    }

    public function isSupported(): bool
    {
        if (PHP_OS_FAMILY !== 'Linux') {
            return false;
        }

        try {
            return Process::timeout(10)->run($this->iptables . ' -n -L INPUT >/dev/null 2>&1')->successful();
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Whether the containment chains are installed, or null when it cannot be
     * determined.
     *
     * Three states, not two, and the third one is the whole point of this
     * method existing in this shape.
     *
     * The previous version returned a bool, collapsing "the chain is not there"
     * and "the question could not be answered" into the same `false`. Measured
     * on this host, those two are different exit codes and only one of them
     * means the host is free:
     *
     *   root, chain absent   rc=1  "iptables: No chain/target/match by that name."
     *   root, chain present  rc=0
     *   www-data, any query  rc=4  "Permission denied (you must be root)"
     *
     * The agent runs both as root, from the watchdog, and as www-data, from
     * `php artisan schedule:work`. So the permission case is not hypothetical:
     * on the www-data path every query answered rc=4, and a bool-returning
     * probe reported the host as not isolated.
     *
     * What that caused is the worst divergence in the subsystem.
     * `EdrResponder::reconcile()` treats "not active" as proof that the rules
     * are gone and marks the ledger reverted with the note
     * `rules_absent_at_reconcile`. So the root watchdog isolates a host, the
     * www-data scheduler fails to read iptables, the ledger records the
     * isolation as lifted, and the Hub is told the host is fine — while the
     * rules are still in place. And once the ledger says reverted,
     * `expireOverdue()` will never revert it, so the isolation becomes
     * permanent by way of a permission error.
     *
     * `release()` had the mirror of it: an unreadable chain read as a
     * successful teardown.
     *
     * stderr is captured rather than discarded, because that is what
     * distinguishes the cases — the old call redirected it to /dev/null and
     * threw away the only usable signal. Absence is only concluded from
     * iptables actually saying the chain is not there.
     */
    public function state(): ?bool
    {
        if (PHP_OS_FAMILY !== 'Linux') {
            return false;
        }

        try {
            $result = Process::timeout(10)->run($this->iptables . ' -n -L ' . self::CHAIN_OUT);

            if ($result->successful()) {
                return true;
            }

            $stderr = $result->errorOutput() . "\n" . $result->output();

            // The one message that means the chain genuinely is not installed.
            if (stripos($stderr, 'No chain/target/match by that name') !== false) {
                return false;
            }

            Log::warning('[EDR response] Containment state could not be determined', [
                'exit_code' => $result->exitCode(),
                'stderr' => mb_substr(trim($stderr), 0, 300),
            ]);

            return null;
        } catch (\Throwable $e) {
            Log::warning('[EDR response] Containment state probe failed: ' . $e->getMessage());

            return null;
        }
    }

    /**
     * True only when the chains are known to be installed.
     *
     * Deliberately not the inverse of "free": `!isActive()` is true both for a
     * host that is not isolated and for a host whose state is unknown, which is
     * exactly the conflation that made an unreadable iptables look like a
     * lifted isolation. Anything that acts on the absence of containment must
     * call `state()` and handle null.
     */
    public function isActive(): bool
    {
        return $this->state() === true;
    }

    /**
     * Work out every address that must stay reachable.
     *
     * @return array{addresses: array<int, string>, dns: array<int, string>, hub_host: ?string}
     */
    public function resolveAllowlist(string $hubUrl, array $extra = []): array
    {
        $addresses = [];
        $hubHost = null;

        $host = parse_url($hubUrl, PHP_URL_HOST);
        if (is_string($host) && $host !== '') {
            $hubHost = $host;

            if (filter_var($host, FILTER_VALIDATE_IP)) {
                $addresses[] = $host;
            } else {
                // Every A record, not just the first: the Hub may sit behind
                // a load balancer or CDN, and pinning one address would strand
                // us the moment DNS hands out a different one.
                foreach ((array) @dns_get_record($host, DNS_A) as $record) {
                    if (!empty($record['ip'])) {
                        $addresses[] = $record['ip'];
                    }
                }

                $viaGethostbyname = gethostbyname($host);
                if ($viaGethostbyname !== $host && filter_var($viaGethostbyname, FILTER_VALIDATE_IP)) {
                    $addresses[] = $viaGethostbyname;
                }
            }
        }

        // DNS has to keep working, because the Hub's address may change while
        // the host is contained and we would have no way to follow it.
        $dns = $this->resolvers();

        foreach ($extra as $address) {
            if (filter_var($address, FILTER_VALIDATE_IP)) {
                $addresses[] = $address;
            }
        }

        return [
            'addresses' => array_values(array_unique($addresses)),
            'dns' => $dns,
            'hub_host' => $hubHost,
        ];
    }

    /**
     * @return array<int, string>
     */
    private function resolvers(): array
    {
        $servers = [];

        foreach (['/etc/resolv.conf', '/run/systemd/resolve/resolv.conf'] as $file) {
            foreach ((array) @file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
                if (preg_match('/^\s*nameserver\s+(\S+)/', $line, $m)
                    && filter_var($m[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)
                ) {
                    $servers[] = $m[1];
                }
            }
        }

        return array_values(array_unique($servers));
    }

    /**
     * Apply containment.
     *
     * @param string $hubUrl        the Hub we must not cut ourselves off from
     * @param array  $extraAllowed  additional addresses to preserve
     * @param bool   $verify        confirm the Hub is still reachable afterwards
     *
     * @return array{success:bool, error:?string, restore_data:?array, result:?array}
     */
    public function isolate(string $hubUrl, array $extraAllowed = [], bool $verify = true): array
    {
        if (!$this->isSupported()) {
            return $this->failure('iptables_unavailable');
        }

        $state = $this->state();

        if ($state === true) {
            return $this->failure('already_isolated');
        }

        if ($state === null) {
            // If iptables cannot be read it almost certainly cannot be written
            // either, and applying rules without knowing the current state
            // risks a half-configured chain that neither isolates nor releases
            // cleanly.
            return $this->failure('containment_state_unknown');
        }

        $allow = $this->resolveAllowlist($hubUrl, $extraAllowed);

        // Refusing here is the whole point. Isolating a host we cannot reach
        // afterwards produces an endpoint that is off the network with no way
        // to be told to come back.
        if ($allow['addresses'] === []) {
            Log::error('[EDR response] Refusing to isolate: Hub address could not be resolved', [
                'hub_url' => $hubUrl,
            ]);

            return $this->failure('hub_unresolvable');
        }

        $commands = $this->buildRules($allow);

        $applied = [];

        foreach ($commands as $command) {
            try {
                $result = Process::timeout(20)->run($command);
            } catch (\Exception $e) {
                $this->teardown($applied);

                return $this->failure('rule_failed: ' . $e->getMessage());
            }

            if (!$result->successful()) {
                // Partial rule sets are worse than none: they can drop traffic
                // without the allowlist being in place yet.
                $this->teardown($applied);

                return $this->failure('rule_failed: ' . trim($result->errorOutput() ?: $result->output()));
            }

            $applied[] = $command;
        }

        if ($verify && !$this->hubReachable($hubUrl)) {
            Log::error('[EDR response] Hub unreachable after isolation, rolling back immediately');
            $this->release();

            return $this->failure('hub_unreachable_after_isolation');
        }

        Log::warning('[EDR response] Host network-isolated', [
            'allowed' => $allow['addresses'],
            'dns' => $allow['dns'],
        ]);

        $restoreData = [
            'chains' => [self::CHAIN_OUT, self::CHAIN_IN],
            'allowed' => $allow['addresses'],
            'dns' => $allow['dns'],
            'hub_host' => $allow['hub_host'],
            'applied_rules' => count($applied),
        ];

        return [
            'success' => true,
            'error' => null,
            'restore_data' => $restoreData,
            'result' => [
                'allowed' => $allow['addresses'],
                'dns' => $allow['dns'],
                'rules' => count($applied),
                'verified' => $verify,
            ],
        ];
    }

    /**
     * The rules, in the order they must be applied: chains first, allowlist
     * entries next, the drop last, and only then the jumps that make any of
     * it live. Inserting the jump before the allowlist would cut the Hub for
     * the instant in between.
     *
     * @return array<int, string>
     */
    private function buildRules(array $allow): array
    {
        $ipt = $this->iptables;
        $out = self::CHAIN_OUT;
        $in = self::CHAIN_IN;

        $commands = [
            "{$ipt} -N {$out}",
            "{$ipt} -N {$in}",
            // Loopback: cutting it breaks local services for no security gain.
            "{$ipt} -A {$out} -o lo -j RETURN",
            "{$ipt} -A {$in} -i lo -j RETURN",
        ];

        foreach ($allow['addresses'] as $address) {
            $escaped = escapeshellarg($address);
            $commands[] = "{$ipt} -A {$out} -d {$escaped} -j RETURN";
            $commands[] = "{$ipt} -A {$in} -s {$escaped} -j RETURN";
        }

        foreach ($allow['dns'] as $resolver) {
            $escaped = escapeshellarg($resolver);
            $commands[] = "{$ipt} -A {$out} -d {$escaped} -p udp --dport 53 -j RETURN";
            $commands[] = "{$ipt} -A {$out} -d {$escaped} -p tcp --dport 53 -j RETURN";
        }

        // Inbound replies to our own allowed traffic. Deliberately not
        // mirrored on the outbound side: letting established connections out
        // would leave an attacker's existing C2 session running, which is
        // exactly what containment is for.
        $commands[] = "{$ipt} -A {$in} -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN";

        // DROP rather than REJECT: no need to tell whatever is on the host
        // that it has been contained.
        $commands[] = "{$ipt} -A {$out} -j DROP";
        $commands[] = "{$ipt} -A {$in} -j DROP";

        // Live last.
        $commands[] = "{$ipt} -I OUTPUT 1 -j {$out}";
        $commands[] = "{$ipt} -I INPUT 1 -j {$in}";

        return $commands;
    }

    /**
     * Remove containment. Safe to call when nothing is installed.
     *
     * @return array{success:bool, error:?string, result:?array}
     */
    public function release(): array
    {
        if (!$this->isSupported()) {
            return ['success' => false, 'error' => 'iptables_unavailable', 'result' => null];
        }

        $ipt = $this->iptables;
        $errors = [];

        // Jumps first, so the chains stop taking effect before they are
        // emptied — the reverse order would briefly leave empty chains
        // dropping nothing, which is harmless, but this way there is never a
        // moment where a half-flushed chain is still live.
        foreach ([
            "{$ipt} -D OUTPUT -j " . self::CHAIN_OUT,
            "{$ipt} -D INPUT -j " . self::CHAIN_IN,
        ] as $command) {
            $this->runIgnoringMissing($command, $errors);
        }

        foreach ([self::CHAIN_OUT, self::CHAIN_IN] as $chain) {
            $this->runIgnoringMissing("{$ipt} -F {$chain}", $errors);
            $this->runIgnoringMissing("{$ipt} -X {$chain}", $errors);
        }

        $stillActive = $this->state();

        if ($stillActive === true) {
            Log::error('[EDR response] Containment could not be fully removed', ['errors' => $errors]);

            return ['success' => false, 'error' => 'release_incomplete', 'result' => ['errors' => $errors]];
        }

        if ($stillActive === null) {
            // The teardown commands may well have worked, but claiming success
            // here is how a host stays cut off while the record says it was
            // freed. Reporting it unverified keeps the action in the ledger for
            // the next reconcile pass to settle.
            Log::error('[EDR response] Containment teardown could not be verified', ['errors' => $errors]);

            return ['success' => false, 'error' => 'release_unverified', 'result' => ['errors' => $errors]];
        }

        Log::warning('[EDR response] Network isolation lifted');

        return ['success' => true, 'error' => null, 'result' => ['errors' => $errors]];
    }

    /**
     * Undo a partially applied rule set.
     */
    private function teardown(array $applied): void
    {
        if ($applied === []) {
            return;
        }

        Log::warning('[EDR response] Rolling back partial containment', ['applied' => count($applied)]);
        $this->release();
    }

    private function runIgnoringMissing(string $command, array &$errors): void
    {
        try {
            $result = Process::timeout(20)->run($command . ' 2>&1');

            if (!$result->successful()) {
                $output = trim($result->output());

                // "No chain/target/match by that name" just means it was not
                // there, which is the desired end state.
                if (!str_contains($output, 'No chain') && !str_contains($output, 'does not exist')) {
                    $errors[] = $output;
                }
            }
        } catch (\Exception $e) {
            $errors[] = $e->getMessage();
        }
    }

    /**
     * Can we still talk to the Hub? A plain TCP connect is enough — we are
     * checking the leash, not the application.
     */
    public function hubReachable(string $hubUrl, int $timeoutSeconds = 10): bool
    {
        $host = parse_url($hubUrl, PHP_URL_HOST);
        if (!is_string($host) || $host === '') {
            return false;
        }

        $scheme = parse_url($hubUrl, PHP_URL_SCHEME) ?: 'https';
        $port = parse_url($hubUrl, PHP_URL_PORT) ?: ($scheme === 'http' ? 80 : 443);

        $handle = @fsockopen($host, (int) $port, $errno, $errstr, $timeoutSeconds);

        if ($handle === false) {
            Log::warning('[EDR response] Hub reachability check failed', [
                'host' => $host,
                'port' => $port,
                'error' => $errstr,
            ]);

            return false;
        }

        fclose($handle);

        return true;
    }

    public function getStatus(): array
    {
        $state = $this->state();

        return [
            'supported' => $this->isSupported(),
            // Kept as a bool for the existing contract, but only true when the
            // chains are known to be present.
            'active' => $state === true,
            // The distinction the bool cannot carry. A consumer that treats
            // `active: false` as "this host is free" needs to see this.
            'state' => $state === null ? 'unknown' : ($state ? 'active' : 'inactive'),
            'chains' => [self::CHAIN_OUT, self::CHAIN_IN],
        ];
    }

    private function failure(string $reason): array
    {
        return ['success' => false, 'error' => $reason, 'restore_data' => null, 'result' => null];
    }
}
