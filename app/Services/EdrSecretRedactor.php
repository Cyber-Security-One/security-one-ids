<?php

namespace App\Services;

/**
 * Strips credentials out of captured command lines.
 *
 * Process telemetry is unusually dangerous to store: argv routinely carries
 * passwords, tokens and keys, and an EDR captures every exec on the host.
 * This is not hypothetical — the first alerts produced during development
 * contained a live database password, because an operator had run
 * `docker exec -e MYSQL_PWD=... mysql ...` and the sensor faithfully
 * recorded it.
 *
 * Redaction happens at write time, so secrets never reach the spool, the
 * Hub, a support bundle, or a backup. Detection is unaffected: rules run
 * against the raw command line before this point.
 *
 * This is the primary control, not encryption. A spool encrypted with a key
 * sitting in the same .env protects against a stolen disk and nothing else —
 * an attacker with root already has both halves. Removing the secret removes
 * the exposure regardless of who reads the file.
 */
class EdrSecretRedactor
{
    public const MASK = '[REDACTED]';

    /**
     * Each pattern must capture the secret in group 1 so the surrounding
     * context — which is what makes the event legible to an analyst — is
     * preserved.
     *
     * @var array<int, string>
     */
    private const PATTERNS = [
        // --password=secret / --token secret and friends.
        // The boundary is `(?<![\w-])`, not `\b`: a word boundary does not
        // exist between a space and a dash, so `\b--password` never matches.
        '/(?<![\w-])--?(?:password|passwd|pwd|pass|token|api[-_]?key|apikey|secret|auth)(?:=|\s+)(\S+)/i',

        // MySQL's attached form, `-phunter2`. Scoped to the mysql family
        // because a bare `-p` is a port flag in most other tools.
        '/\b(?:mysql|mysqldump|mysqladmin|mariadb)\b[^|;]*?\s-p(\S+)/i',

        // Environment-style assignments: MYSQL_PWD=x, PGPASSWORD=x, API_TOKEN=x.
        '/\b(?:[A-Z0-9_]*(?:PASSWORD|PASSWD|PWD|TOKEN|SECRET|APIKEY|API_KEY|ACCESS_KEY)[A-Z0-9_]*)=(\S+)/',

        // HTTP auth headers, typically via curl -H.
        '/\b(?:Authorization|Proxy-Authorization)\s*:\s*(?:Bearer|Basic|Token)?\s*([^"\'\s]+)/i',

        // curl -u user:password — only the password half.
        '/(?<![\w-])-u\s+[^:\s]+:(\S+)/',

        // AWS access key ids are directly identifying.
        '/\b((?:AKIA|ASIA|AIDA|AROA)[0-9A-Z]{16})\b/',

        // Slack / GitHub / generic long-lived token shapes.
        '/\b(xox[baprs]-[0-9A-Za-z-]{10,})/',
        '/\b(gh[pousr]_[0-9A-Za-z]{20,})/',

        // JWTs.
        '/\b(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})/',

        // Inline private key material.
        '/(-----BEGIN[A-Z ]*PRIVATE KEY-----[\s\S]*?-----END[A-Z ]*PRIVATE KEY-----)/',
    ];

    /**
     * Replace every captured secret with the mask, leaving the rest of the
     * command line intact.
     */
    public function redact(?string $value): ?string
    {
        if ($value === null || $value === '') {
            return $value;
        }

        foreach (self::PATTERNS as $pattern) {
            $value = preg_replace_callback(
                $pattern,
                static function (array $m): string {
                    // Rebuild the match with just the captured secret masked,
                    // so `--password=hunter2` becomes `--password=[REDACTED]`
                    // rather than losing the flag name entirely.
                    $offset = strpos($m[0], $m[1]);

                    if ($offset === false) {
                        return self::MASK;
                    }

                    return substr($m[0], 0, $offset) . self::MASK . substr($m[0], $offset + strlen($m[1]));
                },
                $value
            ) ?? $value;
        }

        return $value;
    }

    /**
     * True when redaction would change the value — used to flag events whose
     * command line has been altered, so an analyst knows the difference
     * between "no arguments" and "arguments removed".
     */
    public function containsSecret(?string $value): bool
    {
        return $value !== null && $value !== '' && $this->redact($value) !== $value;
    }
}
